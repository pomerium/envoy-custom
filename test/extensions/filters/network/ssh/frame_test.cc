#include "source/extensions/filters/network/ssh/frame.h"
#include "test/test_common/test_common.h"
#include "gtest/gtest.h"
#include "absl/random/random.h"
#include "source/common/stream_info/filter_state_impl.h"

namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec {

static absl::BitGen rng;

class TestFilterStateObject : public StreamInfo::FilterState::Object {};

TEST(SSHRequestHeaderFrameTest, RequestHeaderFrameImpl) {
  auto obj1Ptr = std::make_shared<TestFilterStateObject>();
  auto obj2Ptr = std::make_shared<TestFilterStateObject>();
  StreamInfo::FilterStateImpl filterState(StreamInfo::FilterState::LifeSpan::FilterChain);
  filterState.setData("obj1", obj1Ptr, StreamInfo::FilterState::StateType::Mutable,
                      StreamInfo::FilterState::LifeSpan::FilterChain,
                      StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnectionOnce);
  filterState.setData("obj2", obj2Ptr, StreamInfo::FilterState::StateType::Mutable,
                      StreamInfo::FilterState::LifeSpan::FilterChain,
                      StreamInfo::StreamSharingMayImpactPooling::None);

  SSHRequestHeaderFrame frame("foo", 1234, filterState);

  EXPECT_EQ("foo", frame.host());
  EXPECT_EQ("ssh", frame.protocol());
  EXPECT_EQ("", frame.path());
  EXPECT_EQ("", frame.method());
  EXPECT_EQ(1234, frame.frameFlags().streamId());
  auto objs = frame.downstreamSharedFilterStateObjects();
  ASSERT_TRUE(objs.has_value());
  EXPECT_EQ(1, objs->size());
  EXPECT_EQ("obj1", objs->at(0).name_);
  EXPECT_EQ(StreamInfo::FilterState::StateType::Mutable, objs->at(0).state_type_);
  EXPECT_EQ(StreamInfo::StreamSharingMayImpactPooling::None, objs->at(0).stream_sharing_);
  EXPECT_EQ(obj1Ptr, objs->at(0).data_);
}

TEST(SSHRequestHeaderFrameTest, FrameFlags) {
  auto streamId = absl::Uniform<stream_id_t>(rng);

  SSHRequestHeaderFrame frame("foo", streamId, StreamInfo::FilterStateImpl{StreamInfo::FilterState::LifeSpan::FilterChain});
  auto flags = frame.frameFlags();
  EXPECT_EQ(streamId, flags.streamId());
  EXPECT_EQ(false, flags.endStream());
  EXPECT_EQ(false, flags.oneWayStream());
  EXPECT_EQ(false, flags.drainClose());
  EXPECT_EQ(false, flags.heartbeat());
  EXPECT_EQ(RequestHeader | EffectiveHeader, flags.frameTags());
}

TEST(SSHResponseHeaderFrameTest, HeaderFrameImpl) {
  EXPECT_EQ("ssh", SSHResponseHeaderFrame({}, {}).protocol());
}

TEST(SSHResponseHeaderFrameTest, Message) {
  wire::DebugMsg d;
  d.message->resize(32); // size needs to be larger than 16 to avoid short string optimization
  auto addr = d.message->data();
  SSHResponseHeaderFrame frame(wire::Message{std::move(d)}, EffectiveHeader);
  EXPECT_EQ(addr, frame.message().message.get<wire::DebugMsg>().message->data());

  EXPECT_STATIC_ASSERT(std::is_same_v<wire::Message&, decltype(frame.message())>);
  EXPECT_STATIC_ASSERT(std::is_same_v<const wire::Message&, decltype(std::as_const(frame).message())>);
}

TEST(SSHResponseHeaderFrameTest, StreamID) {
  SSHResponseHeaderFrame frame(wire::Message{wire::DebugMsg{}}, {});
  EXPECT_EQ(0, frame.streamId());
  frame.setStreamId(1234);
  EXPECT_EQ(1234, frame.streamId());
}

TEST(SSHResponseHeaderFrameTest, FrameFlags) {
  for (auto extraTag : {FrameTags(0), EffectiveCommon, EffectiveHeader, Sentinel, Error}) {
    SSHResponseHeaderFrame frame(wire::Message{wire::DebugMsg{}}, extraTag);
    auto streamId = absl::Uniform<stream_id_t>(rng);
    frame.setStreamId(streamId);
    auto flags = frame.frameFlags();
    EXPECT_EQ(streamId, flags.streamId());
    EXPECT_EQ(extraTag == Error, flags.endStream());
    EXPECT_EQ(false, flags.oneWayStream());
    EXPECT_EQ(extraTag == Error, flags.drainClose());
    EXPECT_EQ(false, flags.heartbeat());
    EXPECT_EQ(ResponseHeader | extraTag, flags.frameTags());
  }
}

TEST(SSHRequestCommonFrameTest, FrameFlags) {
  // tags can only be RequestCommon|EffectiveCommon for this frame type
  SSHRequestCommonFrame frame(wire::Message{wire::DebugMsg{}});
  auto streamId = absl::Uniform<stream_id_t>(rng);
  frame.setStreamId(streamId);
  auto flags = frame.frameFlags();
  EXPECT_EQ(streamId, flags.streamId());
  EXPECT_EQ(false, flags.endStream());
  EXPECT_EQ(false, flags.oneWayStream());
  EXPECT_EQ(false, flags.drainClose());
  EXPECT_EQ(false, flags.heartbeat());
  EXPECT_EQ(RequestCommon | EffectiveCommon, flags.frameTags());
}

TEST(SSHRequestCommonFrameTest, StreamID) {
  SSHRequestCommonFrame frame(wire::Message{wire::DebugMsg{}});
  EXPECT_EQ(0, frame.streamId());
  frame.setStreamId(1234);
  EXPECT_EQ(1234, frame.streamId());
}

TEST(SSHRequestCommonFrameTest, Message) {
  wire::DebugMsg d;
  d.message->resize(32);
  auto addr = d.message->data();
  SSHRequestCommonFrame frame(wire::Message{std::move(d)});
  EXPECT_EQ(addr, frame.message().message.get<wire::DebugMsg>().message->data());

  EXPECT_STATIC_ASSERT(std::is_same_v<wire::Message&, decltype(frame.message())>);
  EXPECT_STATIC_ASSERT(std::is_same_v<const wire::Message&, decltype(std::as_const(frame).message())>);
}

TEST(SSHResponseCommonFrameTest, FrameFlags) {
  for (auto extraTag : {FrameTags(0), EffectiveCommon, EffectiveHeader, Sentinel, Error}) {
    SSHResponseCommonFrame frame(wire::Message{wire::DebugMsg{}}, extraTag);
    auto streamId = absl::Uniform<stream_id_t>(rng);
    frame.setStreamId(streamId);
    auto flags = frame.frameFlags();
    EXPECT_EQ(streamId, flags.streamId());
    EXPECT_EQ(extraTag == Error, flags.endStream());
    EXPECT_EQ(false, flags.oneWayStream());
    EXPECT_EQ(extraTag == Error, flags.drainClose());
    EXPECT_EQ(false, flags.heartbeat());
    EXPECT_EQ(ResponseCommon | extraTag, flags.frameTags());
  }
}

TEST(SSHResponseCommonFrameTest, StreamID) {
  SSHResponseCommonFrame frame(wire::Message{wire::DebugMsg{}}, {});
  EXPECT_EQ(0, frame.streamId());
  frame.setStreamId(1234);
  EXPECT_EQ(1234, frame.streamId());
}

TEST(SSHResponseCommonFrameTest, Message) {
  wire::DebugMsg d;
  d.message->resize(32);
  auto addr = d.message->data();
  SSHResponseCommonFrame frame(wire::Message{std::move(d)}, EffectiveCommon);
  EXPECT_EQ(addr, frame.message().message.get<wire::DebugMsg>().message->data());

  EXPECT_STATIC_ASSERT(std::is_same_v<wire::Message&, decltype(frame.message())>);
  EXPECT_STATIC_ASSERT(std::is_same_v<const wire::Message&, decltype(std::as_const(frame).message())>);
}

TEST(FrameTest, ExtractFrameMessage) {
  {
    wire::DebugMsg d;
    d.message->resize(32);
    auto addr = d.message->data();
    SSHResponseCommonFrame frame(wire::Message{std::move(d)}, {});
    auto&& extracted = extractFrameMessage(frame);
    EXPECT_EQ(addr, extracted.message.get<wire::DebugMsg>().message->data());
  }
  {
    wire::DebugMsg d;
    d.message->resize(32);
    auto addr = d.message->data();
    SSHResponseHeaderFrame frame(wire::Message{std::move(d)}, {});
    auto extracted = extractFrameMessage(frame);
    EXPECT_EQ(addr, extracted.message.get<wire::DebugMsg>().message->data());
  }
  {
    wire::DebugMsg d;
    d.message->resize(32);
    auto addr = d.message->data();
    SSHRequestCommonFrame frame(wire::Message{std::move(d)});
    auto extracted = extractFrameMessage(frame);
    EXPECT_EQ(addr, extracted.message.get<wire::DebugMsg>().message->data());
  }
  {
    SSHRequestHeaderFrame frame("foo", 1234, StreamInfo::FilterStateImpl{StreamInfo::FilterState::LifeSpan::FilterChain});
    EXPECT_THROW_WITH_MESSAGE(extractFrameMessage(frame),
                              EnvoyException,
                              "bug: extractFrameMessage called with RequestHeader frame");
  }
}

} // namespace Envoy::Extensions::NetworkFilters::GenericProxy::Codec