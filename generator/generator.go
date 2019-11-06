package generator

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"strings"

	yara "github.com/VirusTotal/protoc-gen-yara/pb"
	proto "github.com/golang/protobuf/proto"
	pb "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/jhump/protoreflect/desc"
)

// INDENT are the characters used for indenting code.
const INDENT = "  "

var loopVars = []string{
	"i", "j", "k", "l", "m",
}

type field struct {
	name       string
	isRepeated bool
	isMap      bool
}

// Generator takes a file containing a FileDescriptorSet (a protocol buffer
// defined in https://github.com/protocolbuffers/protobuf/blob/master/src/google/protobuf/descriptor.proto,
// which contains the definition of some other protocol buffer) and generates
// a YARA module for it.
//
// The data in a FileDescriptorSet defines one or more protocol buffers in the
// same way that a set of .proto files would do, but the definiton it's encoded
// as a protocol buffer itself.
//
// Instead of parsing .proto files for understanding the described protocol
// buffers, you can simply unmarshall and process the definition encoded in a
// FileDescriptorSet.
//
// The FileDescriptorSet for a proto can be generated with:
//    protoc --descriptor_set_out=hello.descriptor.pb hello.proto
//
// The hello.descriptor.pb file will contain a description of hello.proto in
// binary form, encoded as a FileDescriptorSet protocol buffer.
//
// By passing hello.descriptor.pb to this compiler you can generate a YARA module
// that is able to read data encoded in the format defined by hello.proto and
// use that data in your rules.
//
type Generator struct {
	fd                *desc.FileDescriptor
	protoName         string
	moduleName        string
	rootMessageName   string
	rootMessageType   *desc.MessageDescriptor
	decl              *strings.Builder
	init              *strings.Builder
	loopLevel         int
	indentantionLevel int
	fieldStack        []field
}

// NewGenerator creates an new module compiler.
func NewGenerator() *Generator {
	return &Generator{
		indentantionLevel: 1,
		decl:              &strings.Builder{},
		init:              &strings.Builder{},
		fieldStack:        make([]field, 0),
	}
}

// Returns the descriptor's name, possibly adding an underscore at the end
// if the name is a C++ keyword. This list was was extracted from:
// https://github.com/protobuf-c/protobuf-c/blob/master/protoc-c/c_helpers.cc
func (g *Generator) cName(d desc.Descriptor) string {
	name := d.GetName()
	switch name {
	case "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break",
		"case", "catch", "char", "class", "compl", "const", "const_cast", "continue",
		"default", "delete", "do", "double", "dynamic_cast", "else", "enum",
		"explicit", "extern", "false", "float", "for", "friend", "goto", "if",
		"inline", "int", "long", "mutable", "namespace", "new", "not", "not_eq",
		"operator", "or", "or_eq", "private", "protected", "public", "register",
		"reinterpret_cast", "return", "short", "signed", "sizeof", "static",
		"static_cast", "struct", "switch", "template", "this", "throw", "true", "try",
		"typedef", "typeid", "typename", "union", "unsigned", "using", "virtual",
		"void", "volatile", "wchar_t", "while", "xor", "xor_eq":
		name += "_"
	}
	return name
}

func (g *Generator) emitEnumDeclarations(d desc.Descriptor) error {
	var enums []*desc.EnumDescriptor
	var types []*desc.MessageDescriptor
	switch v := d.(type) {
	case *desc.FileDescriptor:
		v.GetEnumTypes()
		enums = v.GetEnumTypes()
		types = v.GetMessageTypes()
	case *desc.MessageDescriptor:
		enums = v.GetNestedEnumTypes()
		types = v.GetNestedMessageTypes()
	default:
		panic("Expecting *EnumDescriptor or *MessageDescriptor")
	}
	for _, e := range enums {
		fmt.Fprintf(g.decl,
			"%sbegin_struct(\"%s\");\n",
			g.indentation(), g.cName(e))
		for _, v := range e.GetValues() {
			fmt.Fprintf(g.decl,
				"%s%sdeclare_integer(\"%s\");\n",
				g.indentation(), INDENT, g.cName(v))
		}
		fmt.Fprintf(g.decl,
			"%send_struct(\"%s\");\n",
			g.indentation(), g.cName(e))
	}
	for _, t := range types {
		if len(t.GetNestedEnumTypes()) > 0 {
			fmt.Fprintf(g.decl,
				"%sbegin_struct(\"%s\");\n",
				g.indentation(), g.cName(t))
			g.indentantionLevel++
			if err := g.emitEnumDeclarations(t); err != nil {
				return err
			}
			g.indentantionLevel--
			fmt.Fprintf(g.decl,
				"%send_struct(\"%s\");\n",
				g.indentation(), g.cName(t))
		}
	}
	return nil
}

func (g *Generator) emitEnumInitialization(d desc.Descriptor) error {
	var enums []*desc.EnumDescriptor
	var types []*desc.MessageDescriptor
	switch v := d.(type) {
	case *desc.FileDescriptor:
		enums = v.GetEnumTypes()
		types = v.GetMessageTypes()
	case *desc.MessageDescriptor:
		enums = v.GetNestedEnumTypes()
		types = v.GetNestedMessageTypes()
	default:
		panic("Expecting *EnumDescriptor or *MessageDescriptor")
	}
	indent := strings.Repeat(INDENT, g.indentantionLevel)
	for _, e := range enums {
		for _, v := range e.GetValues() {
			fmt.Fprintf(g.init, "%sset_integer(%d, module_object, \"%s\");\n",
				indent, v.GetNumber(), v.GetFullyQualifiedName())
		}
	}
	for _, t := range types {
		if err := g.emitEnumInitialization(t); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) emitDictDeclaration(f *desc.FieldDescriptor) error {
	kt := f.GetMapKeyType()
	vt := f.GetMapValueType()
	if kt == nil || vt == nil {
		panic("either 'key' or 'value' fields not found in a map entry ")
	}
	// Dictionaries in YARA modules must have string keys, other types of
	// keys are not supported.
	if kt.GetType() != pb.FieldDescriptorProto_TYPE_STRING {
		return fmt.Errorf(
			"maps with non-string keys are not supported, %s has %s keys",
			f.GetName(), kt.GetType().String())
	}
	switch t := vt.GetType(); t {
	case pb.FieldDescriptorProto_TYPE_BOOL,
		pb.FieldDescriptorProto_TYPE_ENUM,
		pb.FieldDescriptorProto_TYPE_INT32,
		pb.FieldDescriptorProto_TYPE_INT64:
		fmt.Fprintf(g.decl,
			"%sdeclare_integer_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))

	case pb.FieldDescriptorProto_TYPE_FLOAT,
		pb.FieldDescriptorProto_TYPE_DOUBLE:
		fmt.Fprintf(g.decl,
			"%sdeclare_float_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))

	case pb.FieldDescriptorProto_TYPE_STRING:
		fmt.Fprintf(g.decl,
			"%sdeclare_string_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))

	case pb.FieldDescriptorProto_TYPE_MESSAGE:
		fmt.Fprintf(g.decl,
			"%sbegin_struct_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))
		g.indentantionLevel++
		if err := g.emitStructDeclaration(vt.GetMessageType()); err != nil {
			return err
		}
		g.indentantionLevel--
		fmt.Fprintf(g.decl,
			"%send_struct_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))

	default:
		return fmt.Errorf(
			"%s has type %s, which is not supported by YARA modules",
			f.GetName(), t)
	}
	return nil
}

func (g *Generator) emitStructDeclaration(m *desc.MessageDescriptor) error {
	for _, f := range m.GetFields() {
		var postfix string
		if f.IsRepeated() {
			postfix = "_array"
		}
		switch t := f.GetType(); t {
		case pb.FieldDescriptorProto_TYPE_BOOL,
			pb.FieldDescriptorProto_TYPE_ENUM,
			pb.FieldDescriptorProto_TYPE_INT32,
			pb.FieldDescriptorProto_TYPE_INT64:
			fmt.Fprintf(g.decl,
				"%sdeclare_integer%s(\"%s\");\n",
				g.indentation(), postfix, g.cName(f))

		case pb.FieldDescriptorProto_TYPE_FLOAT,
			pb.FieldDescriptorProto_TYPE_DOUBLE:
			fmt.Fprintf(g.decl,
				"%sdeclare_float%s(\"%s\");\n",
				g.indentation(), postfix, g.cName(f))

		case pb.FieldDescriptorProto_TYPE_STRING:
			fmt.Fprintf(g.decl,
				"%sdeclare_string%s(\"%s\");\n",
				g.indentation(), postfix, g.cName(f))

		case pb.FieldDescriptorProto_TYPE_MESSAGE:
			if f.IsMap() {
				if err := g.emitDictDeclaration(f); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(g.decl,
					"%sbegin_struct%s(\"%s\");\n",
					g.indentation(), postfix, g.cName(f))
				g.indentantionLevel++
				if err := g.emitStructDeclaration(f.GetMessageType()); err != nil {
					return err
				}
				g.indentantionLevel--
				fmt.Fprintf(g.decl,
					"%send_struct%s(\"%s\");\n",
					g.indentation(), postfix, g.cName(f))
			}

		default:
			return fmt.Errorf(
				"%s has type %s, which is not supported by YARA modules",
				f.GetName(), t)
		}
	}
	return nil
}

func (g *Generator) loopVar() string {
	if g.loopLevel == 0 {
		return ""
	}
	if g.loopLevel > len(loopVars) {
		panic("too many nested loops")
	}
	return loopVars[g.loopLevel-1]
}

func (g *Generator) enterLoop() {
	g.loopLevel++
}

func (g *Generator) exitLoop() {
	g.loopLevel--
}

func (g *Generator) indentation() string {
	return strings.Repeat(INDENT, g.indentantionLevel)
}

func (g *Generator) pushField(f *desc.FieldDescriptor) {
	g.fieldStack = append(g.fieldStack, field{
		name:       g.cName(f),
		isRepeated: f.IsRepeated(),
		isMap:      f.IsMap()})
}

func (g *Generator) popField() {
	g.fieldStack = g.fieldStack[:len(g.fieldStack)-1]
}

// Returns a list with the names of the N fields at the bottom of the stack,
// ordered from bottom to top. Repeated fields will be indexed with the
// corresponding loop variable starting with "i" for the outer loop and
// continuing with "j", k" and so on.
func (g *Generator) fieldNames(n int) []string {
	if n > len(g.fieldStack) {
		n = len(g.fieldStack)
	}
	result := make([]string, n)
	for i := 0; i < n; i++ {
		f := g.fieldStack[i]
		if f.isRepeated {
			result[i] = fmt.Sprintf("%s[%s]", f.name, loopVars[i])
		} else {
			result[i] = f.name
		}
	}
	return result
}

// Returns a string that will be inserted in the C source code for accessing
// the field at position N in the stack. For example, if the stack contains
// "foo", "bar", "baz", "qux" (where the top of the stack is "qux"), and N is 2,
// the returned string will be "foo->bar->baz". Repeated fields will be indexed
// by the corresponding loop variable, for example if "foo" and "bar" are arrays
// the result will be "foo[i]->bar[j]->baz"".
func (g *Generator) fieldSelectorN(n int) string {
	return "pb->" + strings.Join(g.fieldNames(n), "->")
}

func (g *Generator) fieldSelector() string {
	return g.fieldSelectorN(len(g.fieldStack))
}

func (g *Generator) prefixedField(prefix string) string {
	names := append(
		g.fieldNames(len(g.fieldStack)-1),
		prefix+g.fieldStack[len(g.fieldStack)-1].name)
	return "pb->" + strings.Join(names, "->")
}

func (g *Generator) fmtStr() string {
	ff := make([]string, 0)
	for i, f := range g.fieldStack {
		// If the previous field in the stack is a map this is the "value"
		// field, which shouldn't appear in the format string.
		if i >= 1 && g.fieldStack[i-1].isMap {
			continue
		}
		// The order is important here, fieldStack that are a map are also an
		// repeated, we must check for isMap first.
		if f.isMap {
			ff = append(ff, fmt.Sprintf("%s[%%s]", f.name))
		} else if f.isRepeated {
			ff = append(ff, fmt.Sprintf("%s[%%i]", f.name))
		} else {
			ff = append(ff, f.name)
		}
	}
	return strings.Join(ff, ".")
}

func (g *Generator) fmtArgsStr() string {
	ff := make([]string, 0)
	j := 0
	for i, f := range g.fieldStack {
		if f.isMap {
			ff = append(ff, g.fieldSelectorN(i+1)+"->key")
		} else if f.isRepeated {
			ff = append(ff, loopVars[j])
			j++
		}
	}
	if len(ff) == 0 {
		return ""
	}
	return ", " + strings.Join(ff, ", ")
}

func (g *Generator) emitFieldInitialization(f *desc.FieldDescriptor) error {
	if f.IsRepeated() {
		g.enterLoop()
		defer g.exitLoop()
	}

	g.pushField(f)
	defer g.popField()

	switch f.GetLabel() {
	case pb.FieldDescriptorProto_LABEL_REPEATED:
		fmt.Fprintf(g.init,
			"\n%sfor (int %s = 0; %s < %s; %s++) {\n",
			g.indentation(),
			g.loopVar(),
			g.loopVar(),
			g.prefixedField("n_"),
			g.loopVar())
		g.indentantionLevel++

	case pb.FieldDescriptorProto_LABEL_OPTIONAL:
		// If some "foo" field is optional (supported by proto2 only) the
		// protoc-c compiler generates a "has_foo" field that indicates
		// if the field was present in the data or not. This is done only
		// for certain types like integers, for which there's no way of
		// distinguishing between a zero value and a missing value.
		switch f.GetType() {
		case pb.FieldDescriptorProto_TYPE_BOOL,
			pb.FieldDescriptorProto_TYPE_ENUM,
			pb.FieldDescriptorProto_TYPE_INT32,
			pb.FieldDescriptorProto_TYPE_INT64:
			fmt.Fprintf(g.init,
				"\n%sif (%s) {\n",
				g.indentation(),
				g.prefixedField("has_"))
			g.indentantionLevel++
		}
	}
	switch t := f.GetType(); t {
	case pb.FieldDescriptorProto_TYPE_BOOL,
		pb.FieldDescriptorProto_TYPE_ENUM,
		pb.FieldDescriptorProto_TYPE_INT32,
		pb.FieldDescriptorProto_TYPE_INT64:
		fmt.Fprintf(g.init,
			"%sset_integer(%s, module_object, \"%s\"%s);\n",
			g.indentation(),
			g.fieldSelector(),
			g.fmtStr(),
			g.fmtArgsStr())

	case pb.FieldDescriptorProto_TYPE_FLOAT,
		pb.FieldDescriptorProto_TYPE_DOUBLE:
		fmt.Fprintf(g.init,
			"%sset_float(%s, module_object, \"%s\"%s);\n",
			g.indentation(),
			g.fieldSelector(),
			g.fmtStr(),
			g.fmtArgsStr())

	case pb.FieldDescriptorProto_TYPE_STRING:
		fmt.Fprintf(g.init,
			"%sset_string(%s, module_object, \"%s\"%s);\n",
			g.indentation(),
			g.fieldSelector(),
			g.fmtStr(),
			g.fmtArgsStr())

	case pb.FieldDescriptorProto_TYPE_MESSAGE:
		var err error
		fmt.Fprintf(g.init,
			"\n%sif (%s != NULL) {\n",
			g.indentation(),
			g.fieldSelector())
		g.indentantionLevel++
		if f.IsMap() {
			err = g.emitFieldInitialization(f.GetMapValueType())
		} else {
			err = g.emitStructInitialization(f.GetMessageType())
		}
		g.indentantionLevel--
		if err != nil {
			return err
		}
		fmt.Fprintf(g.init, "%s}\n", g.indentation())

	default:
		return fmt.Errorf(
			"%s has type %s, which is not supported by YARA modules",
			f.GetName(), t)
	}
	switch f.GetLabel() {
	case pb.FieldDescriptorProto_LABEL_REPEATED:
		g.indentantionLevel--
		fmt.Fprintf(g.init, "%s}\n", g.indentation())
	case pb.FieldDescriptorProto_LABEL_OPTIONAL:
		switch f.GetType() {
		case pb.FieldDescriptorProto_TYPE_BOOL,
			pb.FieldDescriptorProto_TYPE_ENUM,
			pb.FieldDescriptorProto_TYPE_INT32,
			pb.FieldDescriptorProto_TYPE_INT64:
			g.indentantionLevel--
			fmt.Fprintf(g.init, "%s}\n", g.indentation())
		}
	}
	return nil
}

func (g *Generator) emitStructInitialization(d *desc.MessageDescriptor) error {
	for _, f := range d.GetFields() {
		if err := g.emitFieldInitialization(f); err != nil {
			return err
		}
	}
	return nil
}

// Parse receives an array of FileDescriptor structs, each of them corresponding
// to a .proto file. Exactly one of those .proto files must define a YARA module
// by including the following options:
//
//   option (yara.module_options) = {
//	   name : "foomodule"
//	   root_message: "FooMessage";
//   };
//
// The source code for the corresponding YARA module is written to the provided
// io.Writer.
func (g *Generator) Parse(fd *desc.FileDescriptor, out io.Writer) error {
	fileOptions := fd.GetOptions()
	// YARA module options appear as a extension of google.protobuf.FileOptions.
	// E_ModuleOptions provides the description for the extension.
	if ext, err := proto.GetExtension(fileOptions, yara.E_ModuleOptions); err == nil {
		opts := ext.(*yara.ModuleOptions)
		g.moduleName = opts.GetName()
		g.rootMessageName = opts.GetRootMessage()
		g.fd = fd
		g.protoName = fd.GetName()
		if g.moduleName == "" {
			return fmt.Errorf(
				"YARA module options found in %s, but name not specified",
				g.protoName)
		}
		if g.rootMessageName == "" {
			return fmt.Errorf(
				"YARA module options found in %s, but root_message not specified",
				g.protoName)
		}
	}
	if g.fd == nil {
		return errors.New("could not find any YARA module options")
	}
	// Search for the root message type specified by the root_message option.
	g.rootMessageType = g.fd.FindMessage(g.rootMessageName)
	if g.rootMessageType == nil {
		return fmt.Errorf(
			"root message type %s not found in %s",
			g.rootMessageName, g.protoName)
	}
	if err := g.emitEnumDeclarations(g.fd); err != nil {
		return err
	}
	if err := g.emitEnumInitialization(g.fd); err != nil {
		return err
	}
	if err := g.emitStructDeclaration(g.rootMessageType); err != nil {
		return err
	}
	if err := g.emitStructInitialization(g.rootMessageType); err != nil {
		return err
	}
	// Build template used for generating the final code.
	tmpl, err := template.New("yara_module").
		Funcs(template.FuncMap{
			"ToLower": strings.ToLower,
		}).
		Parse(moduleTemplate)

	if err != nil {
		panic(err)
	}

	protoName := fd.GetName()

	return tmpl.Execute(out, templateData{
		ModuleName:      g.moduleName,
		IncludeName:     strings.TrimSuffix(protoName, filepath.Ext(protoName)),
		RootStruct:      g.rootMessageName,
		Declarations:    template.HTML(g.decl.String()),
		Initializations: template.HTML(g.init.String()),
	})
}
