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

// Generator takes a FileDescriptor (a helper type which is just a thin wrapper
// around a FileDescriptorProto) and a generates a YARA module for the protocol
// buffer defined by the FileDescriptor. See:
// https://godoc.org/github.com/jhump/protoreflect/desc#FileDescriptor
// https://godoc.org/github.com/golang/protobuf/protoc-gen-go/descriptor#FileDescriptorProto
type Generator struct {
	fd               *desc.FileDescriptor
	protoName        string
	moduleName       string
	rootMessageName  string
	rootMessageType  *desc.MessageDescriptor
	decl             *strings.Builder
	init             *strings.Builder
	loopLevel        int
	indentationLevel int
	fieldStack       []field
}

// NewGenerator creates an new module generator.
func NewGenerator() *Generator {
	return &Generator{
		indentationLevel: 1,
		decl:             &strings.Builder{},
		init:             &strings.Builder{},
		fieldStack:       make([]field, 0),
	}
}

// Parse receive a FileDescriptor describing a .proto file and writes the source
// code for the corresponding YARA module into the provided writer. The .proto
// file must include a snippet similar to the one below.
//
//   import "yara.proto"
//
//   option (yara.module_options) = {
//	   name : "foomodule"
//	   root_message: "FooMessage";
//   };
//
// These options are required for the generator to be able to genereate the YARA
// module.
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

type typeClass int

const (
	typeUnsupported typeClass = iota
	typeInteger
	typeString
	typeBytes
	typeFloat
	typeStruct
)

func (g *Generator) typeClass(t pb.FieldDescriptorProto_Type) typeClass {
	switch t {
	case pb.FieldDescriptorProto_TYPE_BOOL,
		pb.FieldDescriptorProto_TYPE_ENUM,
		pb.FieldDescriptorProto_TYPE_INT32,
		pb.FieldDescriptorProto_TYPE_INT64,
		pb.FieldDescriptorProto_TYPE_SINT32,
		pb.FieldDescriptorProto_TYPE_SINT64,
		pb.FieldDescriptorProto_TYPE_SFIXED32,
		pb.FieldDescriptorProto_TYPE_SFIXED64:
		return typeInteger
	case pb.FieldDescriptorProto_TYPE_STRING:
		return typeString
	case pb.FieldDescriptorProto_TYPE_BYTES:
		return typeBytes
	case pb.FieldDescriptorProto_TYPE_FLOAT,
		pb.FieldDescriptorProto_TYPE_DOUBLE:
		return typeFloat
	case pb.FieldDescriptorProto_TYPE_MESSAGE:
		return typeStruct
	}
	return typeUnsupported
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

// INDENT are the characters used for indenting code.
const INDENT = "  "

func (g *Generator) indentation() string {
	return strings.Repeat(INDENT, g.indentationLevel)
}

var loopVars = []string{
	"i", "j", "k", "l", "m",
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

type field struct {
	name        string
	messageType string
	isRepeated  bool
	isMap       bool
}

func (g *Generator) pushField(f *desc.FieldDescriptor) error {
	var messageType string
	// If the field is of message type, make sure that none of its ancestors
	// have the same type. If not, it means that we have a recursive message
	// type.
	if t := f.GetMessageType(); t != nil {
		messageType = t.GetFullyQualifiedName()
		for _, f := range g.fieldStack {
			if f.messageType == messageType {
				return fmt.Errorf("recursive message type: %s", messageType)
			}
		}
	}
	g.fieldStack = append(g.fieldStack, field{
		name:        g.cName(f),
		messageType: messageType,
		isRepeated:  f.IsRepeated(),
		isMap:       f.IsMap()})
	return nil
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
	loopDepth := 0
	for i := 0; i < n; i++ {
		f := g.fieldStack[i]
		if f.isRepeated {
			result[i] = fmt.Sprintf("%s[%s]", f.name, loopVars[loopDepth])
			loopDepth++
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

func (g *Generator) fieldSelectorReplace(f string) string {
	names := append(g.fieldNames(len(g.fieldStack)-1), f)
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
			g.indentationLevel++
			if err := g.emitEnumDeclarations(t); err != nil {
				return err
			}
			g.indentationLevel--
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
	indent := strings.Repeat(INDENT, g.indentationLevel)
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
	switch g.typeClass(vt.GetType()) {
	case typeInteger:
		fmt.Fprintf(g.decl,
			"%sdeclare_integer_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))
	case typeFloat:
		fmt.Fprintf(g.decl,
			"%sdeclare_float_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))
	case typeString, typeBytes:
		fmt.Fprintf(g.decl,
			"%sdeclare_string_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))
	case typeStruct:
		fmt.Fprintf(g.decl,
			"%sbegin_struct_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))
		g.indentationLevel++
		if err := g.emitStructDeclaration(vt.GetMessageType()); err != nil {
			return err
		}
		g.indentationLevel--
		fmt.Fprintf(g.decl,
			"%send_struct_dictionary(\"%s\");\n",
			g.indentation(), g.cName(f))
	default:
		return fmt.Errorf(
			"%s has type %s, which is not supported by YARA modules",
			f.GetName(), f.GetType())
	}
	return nil
}

func (g *Generator) emitStructDeclaration(m *desc.MessageDescriptor) error {
	for _, f := range m.GetFields() {
		if err := g.pushField(f); err != nil {
			return err
		}
		var postfix string
		if f.IsRepeated() {
			postfix = "_array"
		}
		switch g.typeClass(f.GetType()) {
		case typeInteger:
			fmt.Fprintf(g.decl,
				"%sdeclare_integer%s(\"%s\");\n",
				g.indentation(), postfix, g.cName(f))
		case typeFloat:
			fmt.Fprintf(g.decl,
				"%sdeclare_float%s(\"%s\");\n",
				g.indentation(), postfix, g.cName(f))
		case typeString, typeBytes:
			fmt.Fprintf(g.decl,
				"%sdeclare_string%s(\"%s\");\n",
				g.indentation(), postfix, g.cName(f))
		case typeStruct:
			if f.IsMap() {
				if err := g.emitDictDeclaration(f); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(g.decl,
					"%sbegin_struct%s(\"%s\");\n",
					g.indentation(), postfix, g.cName(f))
				g.indentationLevel++
				if err := g.emitStructDeclaration(f.GetMessageType()); err != nil {
					return err
				}
				g.indentationLevel--
				fmt.Fprintf(g.decl,
					"%send_struct%s(\"%s\");\n",
					g.indentation(), postfix, g.cName(f))
			}
		default:
			return fmt.Errorf(
				"%s has type %s, which is not supported by YARA modules",
				f.GetName(), f.GetType())
		}
		g.popField()
	}
	return nil
}

func (g *Generator) closeBlock() {
	g.indentationLevel--
	fmt.Fprintf(g.init, "%s}\n", g.indentation())
}

func (g *Generator) emitFieldInitialization(f *desc.FieldDescriptor) error {
	if f.IsRepeated() {
		g.enterLoop()
		defer g.exitLoop()
	}

	if err := g.pushField(f); err != nil {
		return err
	}
	defer g.popField()

	if oneof := f.GetOneOf(); oneof != nil {
		fmt.Fprintf(g.init,
			"\n%sif (%s == %d) {\n",
			g.indentation(),
			// Don't use g.cName here. If the name is a C keyword like "for",
			// the final name is "for_case", not "for__case". The "_case"
			// postfix already avoids the collision with the keyword.
			g.fieldSelectorReplace(oneof.GetName()+"_case"),
			f.GetNumber())
		g.indentationLevel++
		defer g.closeBlock()
	}

	switch f.GetLabel() {
	case pb.FieldDescriptorProto_LABEL_REPEATED:
		fmt.Fprintf(g.init,
			"\n%sfor (int %s = 0; %s < %s; %s++) {\n",
			g.indentation(),
			g.loopVar(),
			g.loopVar(),
			// Even if the "n_" prefix avoids any possible collision with a C
			// keywords, the final name gets the underscore appended. If the
			// name is "for", it gets converted to "n_for_".
			g.fieldSelectorReplace("n_"+g.cName(f)),
			g.loopVar())
		g.indentationLevel++
		defer g.closeBlock()
	case pb.FieldDescriptorProto_LABEL_OPTIONAL:
		// In proto2 if some "foo" field is optional the protoc-c compiler
		// generates a "has_foo" field that indicates if the field was present
		// in the data or not. This is done only for scalar types, for which
		// there's no way of distinguishing between the default value and a
		// missing value. For strings, bytes, and messages a NULL value indicates
		// that the field was missing. In proto3 all fields are optional but
		// the "has_foo" field is not generated, instead missing fields will
		// have their default value.
		if !f.GetFile().IsProto3() {
			switch g.typeClass(f.GetType()) {
			case typeInteger, typeFloat:
				fmt.Fprintf(g.init,
					"\n%sif (%s) {\n",
					g.indentation(),
					// Even if the "has_" prefix avoids any possible collision with a C
					// keywords, the final name gets the underscore appended. If the
					// name is "for", it gets converted to "has_for_".
					g.fieldSelectorReplace("has_"+g.cName(f)))
				g.indentationLevel++
				defer g.closeBlock()
			}
		}
	}

	switch g.typeClass(f.GetType()) {
	case typeInteger:
		fmt.Fprintf(g.init,
			"%sset_integer(%s, module_object, \"%s\"%s);\n",
			g.indentation(),
			g.fieldSelector(),
			g.fmtStr(),
			g.fmtArgsStr())
	case typeFloat:
		fmt.Fprintf(g.init,
			"%sset_float(%s, module_object, \"%s\"%s);\n",
			g.indentation(),
			g.fieldSelector(),
			g.fmtStr(),
			g.fmtArgsStr())
	case typeString:
		fmt.Fprintf(g.init,
			"%sset_string(%s, module_object, \"%s\"%s);\n",
			g.indentation(),
			g.fieldSelector(),
			g.fmtStr(),
			g.fmtArgsStr())
	case typeBytes:
		fmt.Fprintf(g.init,
			"%sset_sized_string((const char *) %s.data, %s.len, module_object, \"%s\"%s);\n",
			g.indentation(),
			g.fieldSelector(),
			g.fieldSelector(),
			g.fmtStr(),
			g.fmtArgsStr())
	case typeStruct:
		var err error
		fmt.Fprintf(g.init,
			"\n%sif (%s != NULL) {\n",
			g.indentation(),
			g.fieldSelector())
		g.indentationLevel++
		defer g.closeBlock()
		if f.IsMap() {
			err = g.emitFieldInitialization(f.GetMapValueType())
		} else {
			err = g.emitStructInitialization(f.GetMessageType())
		}
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf(
			"%s has type %s, which is not supported by YARA modules",
			f.GetName(), f.GetType())
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
