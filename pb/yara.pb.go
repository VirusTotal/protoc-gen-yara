// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pb/yara.proto

package yara

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	descriptor "github.com/golang/protobuf/protoc-gen-go/descriptor"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type ModuleOptions struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	RootMessage          string   `protobuf:"bytes,2,opt,name=root_message,json=rootMessage,proto3" json:"root_message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ModuleOptions) Reset()         { *m = ModuleOptions{} }
func (m *ModuleOptions) String() string { return proto.CompactTextString(m) }
func (*ModuleOptions) ProtoMessage()    {}
func (*ModuleOptions) Descriptor() ([]byte, []int) {
	return fileDescriptor_525dc6cd5d3d5c82, []int{0}
}

func (m *ModuleOptions) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ModuleOptions.Unmarshal(m, b)
}
func (m *ModuleOptions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ModuleOptions.Marshal(b, m, deterministic)
}
func (m *ModuleOptions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ModuleOptions.Merge(m, src)
}
func (m *ModuleOptions) XXX_Size() int {
	return xxx_messageInfo_ModuleOptions.Size(m)
}
func (m *ModuleOptions) XXX_DiscardUnknown() {
	xxx_messageInfo_ModuleOptions.DiscardUnknown(m)
}

var xxx_messageInfo_ModuleOptions proto.InternalMessageInfo

func (m *ModuleOptions) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ModuleOptions) GetRootMessage() string {
	if m != nil {
		return m.RootMessage
	}
	return ""
}

type FieldOptions struct {
	Ignore               bool     `protobuf:"varint,1,opt,name=ignore,proto3" json:"ignore,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FieldOptions) Reset()         { *m = FieldOptions{} }
func (m *FieldOptions) String() string { return proto.CompactTextString(m) }
func (*FieldOptions) ProtoMessage()    {}
func (*FieldOptions) Descriptor() ([]byte, []int) {
	return fileDescriptor_525dc6cd5d3d5c82, []int{1}
}

func (m *FieldOptions) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FieldOptions.Unmarshal(m, b)
}
func (m *FieldOptions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FieldOptions.Marshal(b, m, deterministic)
}
func (m *FieldOptions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FieldOptions.Merge(m, src)
}
func (m *FieldOptions) XXX_Size() int {
	return xxx_messageInfo_FieldOptions.Size(m)
}
func (m *FieldOptions) XXX_DiscardUnknown() {
	xxx_messageInfo_FieldOptions.DiscardUnknown(m)
}

var xxx_messageInfo_FieldOptions proto.InternalMessageInfo

func (m *FieldOptions) GetIgnore() bool {
	if m != nil {
		return m.Ignore
	}
	return false
}

var E_ModuleOptions = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FileOptions)(nil),
	ExtensionType: (*ModuleOptions)(nil),
	Field:         51503,
	Name:          "yara.module_options",
	Tag:           "bytes,51503,opt,name=module_options",
	Filename:      "pb/yara.proto",
}

var E_FieldOptions = &proto.ExtensionDesc{
	ExtendedType:  (*descriptor.FieldOptions)(nil),
	ExtensionType: (*FieldOptions)(nil),
	Field:         51504,
	Name:          "yara.field_options",
	Tag:           "bytes,51504,opt,name=field_options",
	Filename:      "pb/yara.proto",
}

func init() {
	proto.RegisterType((*ModuleOptions)(nil), "yara.ModuleOptions")
	proto.RegisterType((*FieldOptions)(nil), "yara.FieldOptions")
	proto.RegisterExtension(E_ModuleOptions)
	proto.RegisterExtension(E_FieldOptions)
}

func init() { proto.RegisterFile("pb/yara.proto", fileDescriptor_525dc6cd5d3d5c82) }

var fileDescriptor_525dc6cd5d3d5c82 = []byte{
	// 233 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2d, 0x48, 0xd2, 0xaf,
	0x4c, 0x2c, 0x4a, 0xd4, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x01, 0xb1, 0xa5, 0x14, 0xd2,
	0xf3, 0xf3, 0xd3, 0x73, 0x52, 0xf5, 0xc1, 0x62, 0x49, 0xa5, 0x69, 0xfa, 0x29, 0xa9, 0xc5, 0xc9,
	0x45, 0x99, 0x05, 0x25, 0xf9, 0x45, 0x10, 0x75, 0x4a, 0x6e, 0x5c, 0xbc, 0xbe, 0xf9, 0x29, 0xa5,
	0x39, 0xa9, 0xfe, 0x05, 0x25, 0x99, 0xf9, 0x79, 0xc5, 0x42, 0x42, 0x5c, 0x2c, 0x79, 0x89, 0xb9,
	0xa9, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x9c, 0x41, 0x60, 0xb6, 0x90, 0x22, 0x17, 0x4f, 0x51, 0x7e,
	0x7e, 0x49, 0x7c, 0x6e, 0x6a, 0x71, 0x71, 0x62, 0x7a, 0xaa, 0x04, 0x13, 0x58, 0x8e, 0x1b, 0x24,
	0xe6, 0x0b, 0x11, 0x52, 0x52, 0xe3, 0xe2, 0x71, 0xcb, 0x4c, 0xcd, 0x49, 0x81, 0x19, 0x23, 0xc6,
	0xc5, 0x96, 0x99, 0x9e, 0x97, 0x5f, 0x04, 0x31, 0x88, 0x23, 0x08, 0xca, 0xb3, 0x8a, 0xe2, 0xe2,
	0xcb, 0x05, 0xdb, 0x17, 0x9f, 0x0f, 0x55, 0x29, 0xa3, 0x07, 0x71, 0xa4, 0x1e, 0xcc, 0x91, 0x7a,
	0x6e, 0x99, 0x70, 0xe7, 0x48, 0xac, 0x9f, 0xc4, 0xac, 0xc0, 0xa8, 0xc1, 0x6d, 0x24, 0xac, 0x07,
	0xf6, 0x1c, 0x8a, 0x5b, 0x83, 0x78, 0x73, 0x91, 0xb9, 0x56, 0x11, 0x5c, 0xbc, 0x69, 0x20, 0x37,
	0xc0, 0x8d, 0x96, 0xc5, 0x62, 0x34, 0xc2, 0x8d, 0x12, 0x1b, 0xa0, 0x66, 0x0b, 0x41, 0xcc, 0x46,
	0x96, 0x0b, 0xe2, 0x49, 0x43, 0xe2, 0x25, 0xb1, 0x81, 0x0d, 0x30, 0x06, 0x04, 0x00, 0x00, 0xff,
	0xff, 0x79, 0x81, 0x4e, 0x33, 0x65, 0x01, 0x00, 0x00,
}
