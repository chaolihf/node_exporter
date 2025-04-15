// #######################################################################
// ##- Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
// # - iSulad licensed under the Mulan PSL v2.
// # - You can use this software according to the terms and conditions of the Mulan PSL v2.
// # - You may obtain a copy of Mulan PSL v2 at:
// # -     http://license.coscl.org.cn/MulanPSL2
// # - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// # - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// # - PURPOSE.
// # - See the Mulan PSL v2 for more details.
// ##- @Description: generate grpc
// ##- @Author: wujing
// ##- @Create: 2019-04-25
// #######################################################################

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.13.0
// source: isulad.proto

package isula

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type InspectContainerRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id      string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Bformat bool   `protobuf:"varint,2,opt,name=bformat,proto3" json:"bformat,omitempty"`
	Timeout int32  `protobuf:"varint,3,opt,name=timeout,proto3" json:"timeout,omitempty"`
}

func (x *InspectContainerRequest) Reset() {
	*x = InspectContainerRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_isulad_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InspectContainerRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InspectContainerRequest) ProtoMessage() {}

func (x *InspectContainerRequest) ProtoReflect() protoreflect.Message {
	mi := &file_isulad_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InspectContainerRequest.ProtoReflect.Descriptor instead.
func (*InspectContainerRequest) Descriptor() ([]byte, []int) {
	return file_isulad_proto_rawDescGZIP(), []int{0}
}

func (x *InspectContainerRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *InspectContainerRequest) GetBformat() bool {
	if x != nil {
		return x.Bformat
	}
	return false
}

func (x *InspectContainerRequest) GetTimeout() int32 {
	if x != nil {
		return x.Timeout
	}
	return 0
}

type InspectContainerResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ContainerJSON string `protobuf:"bytes,1,opt,name=ContainerJSON,proto3" json:"ContainerJSON,omitempty"`
	Cc            uint32 `protobuf:"varint,2,opt,name=cc,proto3" json:"cc,omitempty"`
	Errmsg        string `protobuf:"bytes,3,opt,name=errmsg,proto3" json:"errmsg,omitempty"`
}

func (x *InspectContainerResponse) Reset() {
	*x = InspectContainerResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_isulad_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InspectContainerResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InspectContainerResponse) ProtoMessage() {}

func (x *InspectContainerResponse) ProtoReflect() protoreflect.Message {
	mi := &file_isulad_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InspectContainerResponse.ProtoReflect.Descriptor instead.
func (*InspectContainerResponse) Descriptor() ([]byte, []int) {
	return file_isulad_proto_rawDescGZIP(), []int{1}
}

func (x *InspectContainerResponse) GetContainerJSON() string {
	if x != nil {
		return x.ContainerJSON
	}
	return ""
}

func (x *InspectContainerResponse) GetCc() uint32 {
	if x != nil {
		return x.Cc
	}
	return 0
}

func (x *InspectContainerResponse) GetErrmsg() string {
	if x != nil {
		return x.Errmsg
	}
	return ""
}

var File_isulad_proto protoreflect.FileDescriptor

var file_isulad_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x69, 0x73, 0x75, 0x6c, 0x61, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a,
	0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x22, 0x5d, 0x0a, 0x17, 0x49, 0x6e,
	0x73, 0x70, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x62, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x62, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x12,
	0x18, 0x0a, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x05,
	0x52, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x22, 0x68, 0x0a, 0x18, 0x49, 0x6e, 0x73,
	0x70, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x24, 0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e,
	0x65, 0x72, 0x4a, 0x53, 0x4f, 0x4e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x43, 0x6f,
	0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x4a, 0x53, 0x4f, 0x4e, 0x12, 0x0e, 0x0a, 0x02, 0x63,
	0x63, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x63, 0x63, 0x12, 0x16, 0x0a, 0x06, 0x65,
	0x72, 0x72, 0x6d, 0x73, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x65, 0x72, 0x72,
	0x6d, 0x73, 0x67, 0x32, 0x68, 0x0a, 0x10, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x54, 0x0a, 0x07, 0x49, 0x6e, 0x73, 0x70, 0x65,
	0x63, 0x74, 0x12, 0x23, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2e,
	0x49, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x24, 0x2e, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69,
	0x6e, 0x65, 0x72, 0x73, 0x2e, 0x49, 0x6e, 0x73, 0x70, 0x65, 0x63, 0x74, 0x43, 0x6f, 0x6e, 0x74,
	0x61, 0x69, 0x6e, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x0c, 0x48,
	0x02, 0x5a, 0x08, 0x2e, 0x2f, 0x3b, 0x69, 0x73, 0x75, 0x6c, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_isulad_proto_rawDescOnce sync.Once
	file_isulad_proto_rawDescData = file_isulad_proto_rawDesc
)

func file_isulad_proto_rawDescGZIP() []byte {
	file_isulad_proto_rawDescOnce.Do(func() {
		file_isulad_proto_rawDescData = protoimpl.X.CompressGZIP(file_isulad_proto_rawDescData)
	})
	return file_isulad_proto_rawDescData
}

var file_isulad_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_isulad_proto_goTypes = []interface{}{
	(*InspectContainerRequest)(nil),  // 0: containers.InspectContainerRequest
	(*InspectContainerResponse)(nil), // 1: containers.InspectContainerResponse
}
var file_isulad_proto_depIdxs = []int32{
	0, // 0: containers.ContainerService.Inspect:input_type -> containers.InspectContainerRequest
	1, // 1: containers.ContainerService.Inspect:output_type -> containers.InspectContainerResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_isulad_proto_init() }
func file_isulad_proto_init() {
	if File_isulad_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_isulad_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			value, ok := v.(*InspectContainerRequest)
			if !ok {
				return nil
			}

			switch v := value; i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_isulad_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			value, ok := v.(*InspectContainerResponse)
			if !ok {
				return nil
			}

			switch v := value; i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_isulad_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_isulad_proto_goTypes,
		DependencyIndexes: file_isulad_proto_depIdxs,
		MessageInfos:      file_isulad_proto_msgTypes,
	}.Build()
	File_isulad_proto = out.File
	file_isulad_proto_rawDesc = nil
	file_isulad_proto_goTypes = nil
	file_isulad_proto_depIdxs = nil
}
