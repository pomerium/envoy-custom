#include "source/extensions/filters/network/ssh/wire/wire_test_common.h"
#include "source/extensions/filters/network/ssh/wire/field.h"

namespace wire::test {

struct TestSubMsg1 {
  using submsg_group = void;
  static constexpr uint32_t submsg_key = 1;
  static constexpr auto submsg_key_encoding = None;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept;
};

struct TestSubMsg2 {
  using submsg_group = void;
  static constexpr uint32_t submsg_key = 2;
  static constexpr auto submsg_key_encoding = None;

  absl::StatusOr<size_t> decode(Envoy::Buffer::Instance& buffer, size_t payload_size) noexcept;
  absl::StatusOr<size_t> encode(Envoy::Buffer::Instance& buffer) const noexcept;
};

struct TestMessage {
  field<std::string> foo;
  sub_message<TestSubMsg1, TestSubMsg2> request;
};

TEST(DecodeSequenceTest, CompileTimeChecks) {
  TestMessage test_msg;

  {
    static constinit auto idx = detail::sub_message_index<decltype(test_msg.foo),
                                                          decltype(test_msg.request)>();
    static_assert(idx.index == 1);
    static_assert(idx.key_field_index == -1);
  }

  {
    static constinit auto idx = detail::sub_message_index<decltype(test_msg.foo),
                                                          decltype(test_msg.request)::key_field_type,
                                                          decltype(test_msg.request)>();
    static_assert(idx.index == 2);
    static_assert(idx.key_field_index == 1);
  }

  {
    static constinit auto idx = detail::sub_message_index<decltype(test_msg.request)::key_field_type,
                                                          decltype(test_msg.foo),
                                                          decltype(test_msg.request)>();
    static_assert(idx.index == 2);
    static_assert(idx.key_field_index == 0);
  }
}

} // namespace wire::test