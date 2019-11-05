// Main package for the protoc-gen-yara plugin.
//
// This program is a plugin for protoc, the Google Protocol Buffers compiler.
// it takes a protocol buffer definition file (.proto) and produces the C
// source file for a YARA module that is able to receive data in the format
// defined by the protocol buffer and use it in your YARA rules.
package main

import (
	"os"
	"path/filepath"
	"strings"

	generator "github.com/VirusTotal/protoc-gen-yara/generator"
	plugins "github.com/jhump/goprotoc/plugins"
)

func replaceExt(fileName, newExt string) string {
	n := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	return n + newExt
}

func plugin(req *plugins.CodeGenRequest, resp *plugins.CodeGenResponse) error {
	for _, f := range req.Files {
		g := generator.NewGenerator()
		o := resp.OutputFile(replaceExt(f.GetName(), ".c"))
		if err := g.Parse(f, o); err != nil {
			return err
		}
		resp.OutputFile("yara.")
	}
	return nil
}

func main() {
	output := os.Stdout
	// Redirect Stdout to Stderr, so that any print statement in the code
	// do not mess up with the plugin's output.
	os.Stdout = os.Stderr
	err := plugins.RunPlugin(os.Args[0], plugin, os.Stdin, output)
	if err != nil {
		os.Exit(1)
	}
}
