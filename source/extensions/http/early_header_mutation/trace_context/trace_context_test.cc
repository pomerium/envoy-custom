#include "source/extensions/http/early_header_mutation/trace_context/trace_context.h"

#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/utility.h"

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
    EXPECT_EQ("0", request_headers.get_("x-pomerium-internal-trace-decision"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent={}", traceid_sampled)},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("1", request_headers.get_("x-pomerium-internal-trace-decision"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent={}", traceid_sampled)},
        {"x-pomerium-internal-trace-decision", "0"},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("1", request_headers.get_("x-pomerium-internal-trace-decision"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent={}", traceid_unsampled)},
        {"x-pomerium-internal-trace-decision", "1"},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_EQ("0", request_headers.get_("x-pomerium-internal-trace-decision"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent=invalid")},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_FALSE(request_headers.has("x-pomerium-internal-trace-decision"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar")},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_FALSE(request_headers.has("x-pomerium-internal-trace-decision"));
  }
  {
    Envoy::Http::TestRequestHeaderMapImpl request_headers{
        {":path", fmt::format("/foo/bar?pomerium_traceparent=00-1-2-??")},
    };
    EXPECT_TRUE(tc.mutate(request_headers, stream_info));
    EXPECT_FALSE(request_headers.has("x-pomerium-internal-trace-decision"));
  }
}

} // namespace Envoy::Extensions::Http::EarlyHeaderMutation