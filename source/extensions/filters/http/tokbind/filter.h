#pragma once

#include "envoy/http/filter.h"
#include "envoy/http/header_map.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TokenBinding {

class TokenBindingFilter : public Http::StreamDecoderFilter {
public:
  TokenBindingFilter(){};
  ~TokenBindingFilter(){};

  void onDestroy() override{};

  Http::FilterHeadersStatus decodeHeaders(Http::HeaderMap& headers, bool) override;

  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override;

  Http::FilterTrailersStatus decodeTrailers(Http::HeaderMap&) override;

  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

  static int ParseSubject(const absl::string_view&, Http::HeaderMap&);

private:
  Http::StreamDecoderFilterCallbacks* callbacks_{};
};

} // namespace TokenBinding
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
