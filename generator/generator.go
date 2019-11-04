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
}

// NewGenerator creates an new module compiler.
func NewGenerator() *Generator {
	return &Generator{
		indentantionLevel: 1,
		decl:              &strings.Builder{},
		init:              &strings.Builder{},
	}
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
	indent := strings.Repeat(INDENT, g.indentantionLevel)
	for _, e := range enums {
		fmt.Fprintf(g.decl, "%sbegin_struct(\"%s\");\n", indent, e.GetName())
		for _, v := range e.GetValues() {
			fmt.Fprintf(g.decl, "%s%sdeclare_integer(\"%s\");\n", indent, INDENT, v.GetName())
		}
		fmt.Fprintf(g.decl, "%send_struct(\"%s\");\n", indent, e.GetName())
	}
	for _, t := range types {
		if len(t.GetNestedEnumTypes()) > 0 {
			fmt.Fprintf(g.decl, "%sbegin_struct(\"%s\");\n", indent, t.GetName())
			g.indentantionLevel++
			if err := g.emitEnumDeclarations(t); err != nil {
				return err
			}
			g.indentantionLevel--
			fmt.Fprintf(g.decl, "%send_struct(\"%s\");\n", indent, t.GetName())
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

func (g *Generator) emitStructDeclaration(m *desc.MessageDescriptor) error {
	for _, f := range m.GetFields() {
		var postfix string
		if f.IsRepeated() {
			postfix = "_array"
		}
		indent := strings.Repeat(INDENT, g.indentantionLevel)
		switch t := f.GetType(); t {
		case pb.FieldDescriptorProto_TYPE_BOOL,
			pb.FieldDescriptorProto_TYPE_ENUM,
			pb.FieldDescriptorProto_TYPE_INT32,
			pb.FieldDescriptorProto_TYPE_INT64:
			fmt.Fprintf(g.decl,
				"%sdeclare_integer%s(\"%s\");\n", indent, postfix, f.GetName())

		case pb.FieldDescriptorProto_TYPE_FLOAT,
			pb.FieldDescriptorProto_TYPE_DOUBLE:
			fmt.Fprintf(g.decl,
				"%sdeclare_float%s(\"%s\");\n", indent, postfix, f.GetName())

		case pb.FieldDescriptorProto_TYPE_STRING:
			fmt.Fprintf(g.decl,
				"%sdeclare_string%s(\"%s\");\n", indent, postfix, f.GetName())

		case pb.FieldDescriptorProto_TYPE_MESSAGE:
			fmt.Fprintf(g.decl,
				"%sbegin_struct%s(\"%s\");\n", indent, postfix, f.GetName())
			g.indentantionLevel++
			if err := g.emitStructDeclaration(f.GetMessageType()); err != nil {
				return err
			}
			g.indentantionLevel--
			fmt.Fprintf(g.decl,
				"%send_struct%s(\"%s\");\n", indent, postfix, f.GetName())

		default:
			return fmt.Errorf(
				"%s has type %s, which is not supported by YARA modules", f.GetName(), t)
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

func (g *Generator) loopVargs() string {
	result := strings.Join(loopVars[0:g.loopLevel], ", ")
	if result != "" {
		result = ", " + result
	}
	return result
}

func (g *Generator) replaceLoopArgs(p string) string {
	for i := 0; i < g.loopLevel; i++ {
		p = strings.Replace(p, "%d", loopVars[i], 1)
	}
	return p
}

func (g *Generator) emitStructInitialization(d *desc.MessageDescriptor, path string) error {
	for _, f := range d.GetFields() {
		var p string
		if path == "" {
			p = f.GetName()
		} else {
			p = fmt.Sprintf("%s->%s", path, f.GetName())
		}
		switch f.GetLabel() {
		case pb.FieldDescriptorProto_LABEL_REPEATED:
			g.loopLevel++
			fmt.Fprintf(g.init,
				"\n%sfor (int %s = 0; %s < pb->%s; %s++) {\n",
				strings.Repeat(INDENT, g.indentantionLevel),
				g.loopVar(),
				g.loopVar(),
				g.replaceLoopArgs(fmt.Sprintf("%sn_%s",
					strings.TrimSuffix(p, f.GetName()),
					f.GetName())),
				g.loopVar())
			g.indentantionLevel++
			p += "[%d]"
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
					"\n%sif (pb->%s) {\n",
					strings.Repeat(INDENT, g.indentantionLevel),
					g.replaceLoopArgs(fmt.Sprintf("%shas_%s",
						strings.TrimSuffix(p, f.GetName()),
						f.GetName())))
				g.indentantionLevel++
			}
		}
		switch t := f.GetType(); t {
		case pb.FieldDescriptorProto_TYPE_BOOL,
			pb.FieldDescriptorProto_TYPE_ENUM,
			pb.FieldDescriptorProto_TYPE_INT32,
			pb.FieldDescriptorProto_TYPE_INT64:
			fmt.Fprintf(g.init,
				"%sset_integer(pb->%s, module_object, \"%s\"%s);\n",
				strings.Repeat(INDENT, g.indentantionLevel),
				g.replaceLoopArgs(p),
				strings.ReplaceAll(p, "->", "."),
				g.loopVargs())

		case pb.FieldDescriptorProto_TYPE_FLOAT,
			pb.FieldDescriptorProto_TYPE_DOUBLE:
			fmt.Fprintf(g.init,
				"%sset_float(pb->%s, module_object, \"%s\"%s);\n",
				strings.Repeat(INDENT, g.indentantionLevel),
				g.replaceLoopArgs(p),
				strings.ReplaceAll(p, "->", "."),
				g.loopVargs())

		case pb.FieldDescriptorProto_TYPE_STRING:
			fmt.Fprintf(g.init,
				"%sset_string(pb->%s, module_object, \"%s\"%s);\n",
				strings.Repeat(INDENT, g.indentantionLevel),
				g.replaceLoopArgs(p),
				strings.ReplaceAll(p, "->", "."),
				g.loopVargs())

		case pb.FieldDescriptorProto_TYPE_MESSAGE:
			indent := strings.Repeat(INDENT, g.indentantionLevel)
			fmt.Fprintf(g.init,
				"\n%sif (pb->%s != NULL) {\n",
				indent,
				g.replaceLoopArgs(p))
			g.indentantionLevel++
			if err := g.emitStructInitialization(f.GetMessageType(), p); err != nil {
				return err
			}
			g.indentantionLevel--
			fmt.Fprintf(g.init, "%s}\n", indent)

		default:
			return fmt.Errorf(
				"%s has type %s, which is not supported by YARA modules", f.GetName(), t)
		}
		switch f.GetLabel() {
		case pb.FieldDescriptorProto_LABEL_REPEATED:
			g.loopLevel--
			g.indentantionLevel--
			fmt.Fprintf(g.init, "%s}\n",
				strings.Repeat(INDENT, g.indentantionLevel))
		case pb.FieldDescriptorProto_LABEL_OPTIONAL:
			switch f.GetType() {
			case pb.FieldDescriptorProto_TYPE_BOOL,
				pb.FieldDescriptorProto_TYPE_ENUM,
				pb.FieldDescriptorProto_TYPE_INT32,
				pb.FieldDescriptorProto_TYPE_INT64:
				g.indentantionLevel--
				fmt.Fprintf(g.init, "%s}\n",
					strings.Repeat(INDENT, g.indentantionLevel))
			}
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
	if err := g.emitStructInitialization(g.rootMessageType, ""); err != nil {
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
