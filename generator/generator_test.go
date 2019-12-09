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
	b, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProto2(t *testing.T) {
	fds := &pb.FileDescriptorSet{}
	err := proto.Unmarshal(loadFile(t, "test_pb2.pb.bin"), fds)
	assert.NoError(t, err)

	fd, err := desc.CreateFileDescriptorFromSet(fds)
	assert.NoError(t, err)

	out := &bytes.Buffer{}
	g := NewGenerator()
	err = g.Parse(fd, out)
	assert.NoError(t, err)
	assert.Equal(t, string(loadFile(t, "test_pb2.c")), out.String())
}

func TestProto3(t *testing.T) {
	fds := &pb.FileDescriptorSet{}
	err := proto.Unmarshal(loadFile(t, "test_pb3.pb.bin"), fds)
	assert.NoError(t, err)

	fd, err := desc.CreateFileDescriptorFromSet(fds)
	assert.NoError(t, err)

	out := &bytes.Buffer{}
	g := NewGenerator()
	err = g.Parse(fd, out)
	assert.NoError(t, err)
	assert.Equal(t, string(loadFile(t, "test_pb3.c")), out.String())
}
