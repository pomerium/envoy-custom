// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v5.26.1
// source: api/extensions/http/early_header_mutation/trace_context/trace_context.proto

package trace_context

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

type TraceContext struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *TraceContext) Reset() {
	*x = TraceContext{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TraceContext) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TraceContext) ProtoMessage() {}

func (x *TraceContext) ProtoReflect() protoreflect.Message {
	mi := &file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TraceContext.ProtoReflect.Descriptor instead.
func (*TraceContext) Descriptor() ([]byte, []int) {
	return file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDescGZIP(), []int{0}
}

var File_api_extensions_http_early_header_mutation_trace_context_trace_context_proto protoreflect.FileDescriptor

var file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDesc = []byte{
	0x0a, 0x4b, 0x61, 0x70, 0x69, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x65, 0x61, 0x72, 0x6c, 0x79, 0x5f, 0x68, 0x65, 0x61, 0x64,
	0x65, 0x72, 0x5f, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f,
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13, 0x70,
	0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x22, 0x0e, 0x0a, 0x0c, 0x54, 0x72, 0x61, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x74, 0x65,
	0x78, 0x74, 0x42, 0x5d, 0x5a, 0x5b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2d,
	0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2f, 0x65, 0x78,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x65, 0x61,
	0x72, 0x6c, 0x79, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x6d, 0x75, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78,
	0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDescOnce sync.Once
	file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDescData = file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDesc
)

func file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDescGZIP() []byte {
	file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDescOnce.Do(func() {
		file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDescData)
	})
	return file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDescData
}

var file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_goTypes = []interface{}{
	(*TraceContext)(nil), // 0: pomerium.extensions.TraceContext
}
var file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_init() }
func file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_init() {
	if File_api_extensions_http_early_header_mutation_trace_context_trace_context_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TraceContext); i {
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
			RawDescriptor: file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_goTypes,
		DependencyIndexes: file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_depIdxs,
		MessageInfos:      file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_msgTypes,
	}.Build()
	File_api_extensions_http_early_header_mutation_trace_context_trace_context_proto = out.File
	file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_rawDesc = nil
	file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_goTypes = nil
	file_api_extensions_http_early_header_mutation_trace_context_trace_context_proto_depIdxs = nil
}
