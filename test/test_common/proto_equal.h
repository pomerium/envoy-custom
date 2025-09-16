#pragma once

#include "source/common/protobuf/utility.h"
#include "gmock/gmock-matchers.h"

// Use instead of Envoy::Grpc::ProtoBufferEq when messages must compare exactly equal, including
// presence of empty messages, default values, etc.
// Modified from envoy test/mocks/grpc/mocks.h.
namespace Envoy {
inline bool protoStrictEqual(const Protobuf::Message& lhs, const Protobuf::Message& rhs,
                             bool ignore_repeated_field_ordering = false) {
  Protobuf::util::MessageDifferencer differencer;
  differencer.set_message_field_comparison(Protobuf::util::MessageDifferencer::EQUAL);
  if (ignore_repeated_field_ordering) {
    differencer.set_repeated_field_comparison(Protobuf::util::MessageDifferencer::AS_SET);
  }
  return differencer.Compare(lhs, rhs);
}

MATCHER_P(ProtoBufferStrictEq, expected, "") { // NOLINT
  typename std::remove_const<decltype(expected)>::type proto;
  if (!proto.ParseFromString(arg->toString())) {
    *result_listener << "\nParse of buffer failed\n";
    return false;
  }
  auto equal = protoStrictEqual(proto, expected);
  if (!equal) {
    *result_listener << "\n"
                     << "=======================Expected proto:===========================\n"
                     << expected.DebugString()
                     << "------------------is not equal to actual proto:------------------\n"
                     << proto.DebugString()
                     << "=================================================================\n";
  }
  return equal;
}

} // namespace Envoy