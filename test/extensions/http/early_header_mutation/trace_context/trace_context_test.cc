#include "source/extensions/http/early_header_mutation/trace_context/trace_context.h"

#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/utility.h"
#include "source/common/common/base64.h"
#include "absl/random/random.h"

#include "gtest/gtest.h"

namespace Envoy::Extensions::Http::EarlyHeaderMutation {

constexpr auto traceid_unsampled = "00-11111111111111111111111111111111-2222222222222222-00";
constexpr auto traceid_sampled = "00-11111111111111111111111111111111-2222222222222222-01";

TEST(TraceContextTest, Mutate) {
  TraceContext tc;
  NiceMock<Envoy::StreamInfo::MockStreamInfo> stream_info;

  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent={}", traceid_unsampled)},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("0", request_headers.get_("x-pomerium-sampling-decision"));
    EXPECT_EQ(traceid_unsampled, request_headers.get_("x-pomerium-traceparent"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent={}&pomerium_tracestate=foo",
                              traceid_unsampled)},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("0", request_headers.get_("x-pomerium-sampling-decision"));
    EXPECT_EQ(traceid_unsampled, request_headers.get_("x-pomerium-traceparent"));
    EXPECT_EQ("foo", request_headers.get_("x-pomerium-tracestate"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent={}", traceid_sampled)},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("1", request_headers.get_("x-pomerium-sampling-decision"));
    EXPECT_EQ(traceid_sampled, request_headers.get_("x-pomerium-traceparent"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent={}", traceid_sampled)},
        {"x-pomerium-sampling-decision", "0"},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("1", request_headers.get_("x-pomerium-sampling-decision"));
    EXPECT_EQ(traceid_sampled, request_headers.get_("x-pomerium-traceparent"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent={}", traceid_unsampled)},
        {"x-pomerium-sampling-decision", "1"},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("0", request_headers.get_("x-pomerium-sampling-decision"));
    EXPECT_EQ(traceid_unsampled, request_headers.get_("x-pomerium-traceparent"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", "/foo/bar?pomerium_traceparent=invalid"},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_FALSE(request_headers.has("x-pomerium-sampling-decision"));
    EXPECT_FALSE(request_headers.has("x-pomerium-traceparent"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", "/foo/bar"},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_FALSE(request_headers.has("x-pomerium-sampling-decision"));
    EXPECT_FALSE(request_headers.has("x-pomerium-traceparent"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", "/foo/bar?pomerium_traceparent=00-1-2-??"},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_FALSE(request_headers.has("x-pomerium-sampling-decision"));
    EXPECT_FALSE(request_headers.has("x-pomerium-traceparent"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {"traceparent", traceid_sampled},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("2222222222222222", request_headers.get_("x-pomerium-external-parent-span"));
    EXPECT_FALSE(request_headers.has("x-pomerium-traceparent"));
  }
  {
    absl::BitGen bitgen;
    const auto traceid_bytes =
        absl::StrCat(absl::HexStringToBytes("11111111111111111111111111111111"), 1);
    EXPECT_EQ(traceid_bytes.size(), 17);
    const auto encoded_traceid = Base64Url::encode(traceid_bytes.c_str(), traceid_bytes.size());
    char random_bytes[64];
    for (int i = 0; i < 64; i++) {
      random_bytes[i] = absl::Uniform<char>(bitgen, -128, 127);
    }
    const auto state = absl::StrCat("foo|bar|", encoded_traceid, "|", random_bytes);
    auto state_encoded = Base64Url::encode(state.c_str(), state.size());
    Base64::completePadding(state_encoded); // match go base64url encoding
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", absl::StrCat("/oauth2/callback?code=xyz&state=", state_encoded)},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("11111111111111111111111111111111", request_headers.get_("x-pomerium-traceid"));
    EXPECT_EQ("1", request_headers.get_("x-pomerium-sampling-decision"));
  }
}

} // namespace Envoy::Extensions::Http::EarlyHeaderMutation