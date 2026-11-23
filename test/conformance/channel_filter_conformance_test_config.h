#pragma once

#include "google/protobuf/message.h"

class ChannelFilterConformanceTestConfig {
public:
  static const char* extension_id;
  static const char* extension_path;
  static const char* channel_filter_name;
  static const char* workspace_name;

  void setUp();

  std::unique_ptr<google::protobuf::Message> newExtensionConfig();
  std::unique_ptr<google::protobuf::Message> newChannelFilterFactoryConfig();
  std::unique_ptr<google::protobuf::Message> newChannelFilterConfig();

  enum FilterProperties : uint32_t {
    FilterAllowsMultipleSessions = 1 << 0,
  };

  FilterProperties filterProperties() const;
};
