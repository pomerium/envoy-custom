// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v5.26.1
// source: api/extensions/tracers/pomerium_otel/pomerium_otel.proto

package pomerium_otel

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
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

type OpenTelemetryConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GrpcService       *v3.GrpcService            `protobuf:"bytes,1,opt,name=grpc_service,json=grpcService,proto3" json:"grpc_service,omitempty"`
	HttpService       *v3.HttpService            `protobuf:"bytes,3,opt,name=http_service,json=httpService,proto3" json:"http_service,omitempty"`
	ServiceName       string                     `protobuf:"bytes,2,opt,name=service_name,json=serviceName,proto3" json:"service_name,omitempty"`
	ResourceDetectors []*v3.TypedExtensionConfig `protobuf:"bytes,4,rep,name=resource_detectors,json=resourceDetectors,proto3" json:"resource_detectors,omitempty"`
	Sampler           *v3.TypedExtensionConfig   `protobuf:"bytes,5,opt,name=sampler,proto3" json:"sampler,omitempty"`
}

func (x *OpenTelemetryConfig) Reset() {
	*x = OpenTelemetryConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OpenTelemetryConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OpenTelemetryConfig) ProtoMessage() {}

func (x *OpenTelemetryConfig) ProtoReflect() protoreflect.Message {
	mi := &file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OpenTelemetryConfig.ProtoReflect.Descriptor instead.
func (*OpenTelemetryConfig) Descriptor() ([]byte, []int) {
	return file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescGZIP(), []int{0}
}

func (x *OpenTelemetryConfig) GetGrpcService() *v3.GrpcService {
	if x != nil {
		return x.GrpcService
	}
	return nil
}

func (x *OpenTelemetryConfig) GetHttpService() *v3.HttpService {
	if x != nil {
		return x.HttpService
	}
	return nil
}

func (x *OpenTelemetryConfig) GetServiceName() string {
	if x != nil {
		return x.ServiceName
	}
	return ""
}

func (x *OpenTelemetryConfig) GetResourceDetectors() []*v3.TypedExtensionConfig {
	if x != nil {
		return x.ResourceDetectors
	}
	return nil
}

func (x *OpenTelemetryConfig) GetSampler() *v3.TypedExtensionConfig {
	if x != nil {
		return x.Sampler
	}
	return nil
}

var File_api_extensions_tracers_pomerium_otel_pomerium_otel_proto protoreflect.FileDescriptor

var file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDesc = []byte{
	0x0a, 0x38, 0x61, 0x70, 0x69, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x73, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75,
	0x6d, 0x5f, 0x6f, 0x74, 0x65, 0x6c, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x5f,
	0x6f, 0x74, 0x65, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13, 0x70, 0x6f, 0x6d, 0x65,
	0x72, 0x69, 0x75, 0x6d, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x1a,
	0x24, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f,
	0x72, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x27, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x27,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x72,
	0x65, 0x2f, 0x76, 0x33, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x6d, 0x69, 0x67, 0x72, 0x61, 0x74,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x93, 0x03, 0x0a, 0x13, 0x4f, 0x70, 0x65, 0x6e, 0x54,
	0x65, 0x6c, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x79, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x5b,
	0x0a, 0x0c, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x47, 0x72, 0x70, 0x63,
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x42, 0x15, 0xf2, 0x98, 0xfe, 0x8f, 0x05, 0x0f, 0x12,
	0x0d, 0x6f, 0x74, 0x6c, 0x70, 0x5f, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x52, 0x0b,
	0x67, 0x72, 0x70, 0x63, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x5b, 0x0a, 0x0c, 0x68,
	0x74, 0x74, 0x70, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x21, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x48, 0x74, 0x74, 0x70, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x42, 0x15, 0xf2, 0x98, 0xfe, 0x8f, 0x05, 0x0f, 0x12, 0x0d, 0x6f, 0x74,
	0x6c, 0x70, 0x5f, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x72, 0x52, 0x0b, 0x68, 0x74, 0x74,
	0x70, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x59, 0x0a, 0x12, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74, 0x6f, 0x72,
	0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x54,
	0x79, 0x70, 0x65, 0x64, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x52, 0x11, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x44, 0x65, 0x74,
	0x65, 0x63, 0x74, 0x6f, 0x72, 0x73, 0x12, 0x44, 0x0a, 0x07, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x54,
	0x79, 0x70, 0x65, 0x64, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x52, 0x07, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x42, 0x4f, 0xba, 0x80,
	0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0x5a, 0x45, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x65, 0x78, 0x74,
	0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x73, 0x2f,
	0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x5f, 0x6f, 0x74, 0x65, 0x6c, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescOnce sync.Once
	file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescData = file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDesc
)

func file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescGZIP() []byte {
	file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescOnce.Do(func() {
		file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescData)
	})
	return file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescData
}

var file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_goTypes = []interface{}{
	(*OpenTelemetryConfig)(nil),     // 0: pomerium.extensions.OpenTelemetryConfig
	(*v3.GrpcService)(nil),          // 1: envoy.config.core.v3.GrpcService
	(*v3.HttpService)(nil),          // 2: envoy.config.core.v3.HttpService
	(*v3.TypedExtensionConfig)(nil), // 3: envoy.config.core.v3.TypedExtensionConfig
}
var file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_depIdxs = []int32{
	1, // 0: pomerium.extensions.OpenTelemetryConfig.grpc_service:type_name -> envoy.config.core.v3.GrpcService
	2, // 1: pomerium.extensions.OpenTelemetryConfig.http_service:type_name -> envoy.config.core.v3.HttpService
	3, // 2: pomerium.extensions.OpenTelemetryConfig.resource_detectors:type_name -> envoy.config.core.v3.TypedExtensionConfig
	3, // 3: pomerium.extensions.OpenTelemetryConfig.sampler:type_name -> envoy.config.core.v3.TypedExtensionConfig
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_init() }
func file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_init() {
	if File_api_extensions_tracers_pomerium_otel_pomerium_otel_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OpenTelemetryConfig); i {
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
			RawDescriptor: file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_goTypes,
		DependencyIndexes: file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_depIdxs,
		MessageInfos:      file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_msgTypes,
	}.Build()
	File_api_extensions_tracers_pomerium_otel_pomerium_otel_proto = out.File
	file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDesc = nil
	file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_goTypes = nil
	file_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_depIdxs = nil
}
