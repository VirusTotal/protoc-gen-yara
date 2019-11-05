package generator

import (
	"bytes"
	"io/ioutil"
	"path/filepath"
	"testing"

	proto "github.com/golang/protobuf/proto"
	pb "github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/jhump/protoreflect/desc"
	"github.com/stretchr/testify/assert"
)

func loadFile(t *testing.T, name string) []byte {
	path := filepath.Join("testdata", name)
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func TestProto2(t *testing.T) {
	fds := &pb.FileDescriptorSet{}
	err := proto.Unmarshal(loadFile(t, "customer.pb.bin"), fds)
	assert.NoError(t, err)

	fd, err := desc.CreateFileDescriptorFromSet(fds)
	assert.NoError(t, err)

	out := &bytes.Buffer{}
	g := NewGenerator()
	g.Parse(fd, out)

	assert.Equal(t, string(loadFile(t, "customer.c")), out.String())
}
