#include "source/extensions/filters/network/ssh/messages.h"

#include "gtest/gtest.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

TEST(PacketEncodingTest, EncodeDecode) {
  KexInitMessage msg{};

  Envoy::Buffer::OwnedImpl buf;
  writePacket(buf, msg);
  auto [packet, err] = readPacket<KexInitMessage>(buf);
  EXPECT_EQ(msg.toString(), packet.toString());
}
} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec