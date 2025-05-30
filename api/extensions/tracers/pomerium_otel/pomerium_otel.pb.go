// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        (unknown)
// source: github.com/pomerium/envoy-custom/api/extensions/tracers/pomerium_otel/pomerium_otel.proto

package pomerium_otel

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type OpenTelemetryConfig struct {
	state             protoimpl.MessageState     `protogen:"open.v1"`
	GrpcService       *v3.GrpcService            `protobuf:"bytes,1,opt,name=grpc_service,json=grpcService,proto3" json:"grpc_service,omitempty"`
	HttpService       *v3.HttpService            `protobuf:"bytes,3,opt,name=http_service,json=httpService,proto3" json:"http_service,omitempty"`
	ServiceName       string                     `protobuf:"bytes,2,opt,name=service_name,json=serviceName,proto3" json:"service_name,omitempty"`
	ResourceDetectors []*v3.TypedExtensionConfig `protobuf:"bytes,4,rep,name=resource_detectors,json=resourceDetectors,proto3" json:"resource_detectors,omitempty"`
	Sampler           *v3.TypedExtensionConfig   `protobuf:"bytes,5,opt,name=sampler,proto3" json:"sampler,omitempty"`
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *OpenTelemetryConfig) Reset() {
	*x = OpenTelemetryConfig{}
	mi := &file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *OpenTelemetryConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OpenTelemetryConfig) ProtoMessage() {}

func (x *OpenTelemetryConfig) ProtoReflect() protoreflect.Message {
	mi := &file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_msgTypes[0]
	if x != nil {
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
	return file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescGZIP(), []int{0}
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

var File_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto protoreflect.FileDescriptor

const file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDesc = "" +
	"\n" +
	"Ygithub.com/pomerium/envoy-custom/api/extensions/tracers/pomerium_otel/pomerium_otel.proto\x12\x13pomerium.extensions\x1a$envoy/config/core/v3/extension.proto\x1a'envoy/config/core/v3/grpc_service.proto\x1a'envoy/config/core/v3/http_service.proto\x1a\x1eudpa/annotations/migrate.proto\x1a\x1dudpa/annotations/status.proto\"\x93\x03\n" +
	"\x13OpenTelemetryConfig\x12[\n" +
	"\fgrpc_service\x18\x01 \x01(\v2!.envoy.config.core.v3.GrpcServiceB\x15\xf2\x98\xfe\x8f\x05\x0f\x12\rotlp_exporterR\vgrpcService\x12[\n" +
	"\fhttp_service\x18\x03 \x01(\v2!.envoy.config.core.v3.HttpServiceB\x15\xf2\x98\xfe\x8f\x05\x0f\x12\rotlp_exporterR\vhttpService\x12!\n" +
	"\fservice_name\x18\x02 \x01(\tR\vserviceName\x12Y\n" +
	"\x12resource_detectors\x18\x04 \x03(\v2*.envoy.config.core.v3.TypedExtensionConfigR\x11resourceDetectors\x12D\n" +
	"\asampler\x18\x05 \x01(\v2*.envoy.config.core.v3.TypedExtensionConfigR\asamplerBO\xba\x80\xc8\xd1\x06\x02\x10\x02ZEgithub.com/pomerium/envoy-custom/api/extensions/tracers/pomerium_otelb\x06proto3"

var (
	file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescOnce sync.Once
	file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescData []byte
)

func file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescGZIP() []byte {
	file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescOnce.Do(func() {
		file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDesc), len(file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDesc)))
	})
	return file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDescData
}

var file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_goTypes = []any{
	(*OpenTelemetryConfig)(nil),     // 0: pomerium.extensions.OpenTelemetryConfig
	(*v3.GrpcService)(nil),          // 1: envoy.config.core.v3.GrpcService
	(*v3.HttpService)(nil),          // 2: envoy.config.core.v3.HttpService
	(*v3.TypedExtensionConfig)(nil), // 3: envoy.config.core.v3.TypedExtensionConfig
}
var file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_depIdxs = []int32{
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

func init() {
	file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_init()
}
func file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_init() {
	if File_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDesc), len(file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_goTypes,
		DependencyIndexes: file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_depIdxs,
		MessageInfos:      file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_msgTypes,
	}.Build()
	File_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto = out.File
	file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_goTypes = nil
	file_github_com_pomerium_envoy_custom_api_extensions_tracers_pomerium_otel_pomerium_otel_proto_depIdxs = nil
}
