#include "extensions/filters/http/tokbind/filter.h"
#include "extensions/filters/http/tokbind/tokbind.h"
#include "common/common/base64.h"
#include "common/common/empty_string.h"
#include "common/http/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TokenBinding {

namespace {
const std::string TOKBIND_EKM_LABEL = "EXPORTER-Token-Binding";

class SecHeaderValues {
public:
  const Http::LowerCaseString TokenBinding{"Sec-Token-Binding"};
  // For the backend.
  struct {
    // The Token Binding ID of the provided Token Binding represented as
    // an "EncodedTokenBindingID".
    const Http::LowerCaseString Provided{"Sec-Provided-Token-Binding-ID"};
    //      The Token Binding ID of the referred Token Binding represented as
    //      an "EncodedTokenBindingID".
    const Http::LowerCaseString Referred{"Sec-Referred-Token-Binding-ID"};
    //      Additional Token Bindings that are sent by the client and
    //      validated by the TTRP are represented as a comma-separated list of
    //      the concatenation of the "EncodedTokenBindingType", a period (".")
    //      character, and the "EncodedTokenBindingID" of each.
    const Http::LowerCaseString Other{"Sec-Other-Token-Binding-ID"};
  } TokenBindingID;
};

typedef ConstSingleton<SecHeaderValues> SecHeaders;

#define RETURN_BAD_REQUEST()                                                                       \
  do {                                                                                             \
    callbacks_->requestInfo().setResponseFlag(RequestInfo::ResponseFlag::FaultInjected);           \
    Http::Utility::sendLocalReply(false, *callbacks_, false, Http::Code::BadRequest, "", false);   \
    return Http::FilterHeadersStatus::StopIteration;                                               \
  } while (0)

} // namespace

Http::FilterHeadersStatus TokenBindingFilter::decodeHeaders(Http::HeaderMap& headers, bool) {

  if (!callbacks_->connection()->ssl())
    RETURN_BAD_REQUEST();
  // TODO(): only support token binding on http/2 connections because they don't
  // support renegotiation.

  int stbh_count = 0;
  headers.iterate(
      [](const Http::HeaderEntry& header, void* context) -> Http::HeaderMap::Iterate {
        if (header.key() == SecHeaders::get().TokenBinding.get().c_str()) {
          auto stbh_count = static_cast<int*>(context);
          stbh_count++;
        }
        return Http::HeaderMap::Iterate::Continue;
      },
      &stbh_count);

  if (stbh_count == 0)
    return Http::FilterHeadersStatus::Continue;
  if (stbh_count != 1)
    RETURN_BAD_REQUEST();

  std::string stbh(headers.get(SecHeaders::get().TokenBinding)->value().getStringView());
  headers.remove(SecHeaders::get().TokenBinding);

  const std::string& stbraw(Base64Url::decode(stbh.c_str()));
  if (stbraw == EMPTY_STRING)
    RETURN_BAD_REQUEST();

  const std::string ekm =
      callbacks_->connection()->ssl()->exportKeyingMaterial(32, TOKBIND_EKM_LABEL);
  if (ekm == EMPTY_STRING)
    // TODO(): make this a server error?
    RETURN_BAD_REQUEST();

  std::vector<TokenBinding> tbs;
  ParseTokenBindingMessage(stbraw, tbs);
  if (!VerifyTokenBindings(tbs, ekm))
    RETURN_BAD_REQUEST();

  int ptb_count, rtb_count = 0;
  for (const TokenBinding& tb : tbs) {
    switch (tb.type()) {
    case PROVIDED_TOKEN_BINDING:
      ptb_count++;
      break;
    case REFERRED_TOKEN_BINDING:
      rtb_count++;
      break;
    }
  }
  if (ptb_count > 1 || rtb_count > 1)
    RETURN_BAD_REQUEST();

  for (const TokenBinding& tb : tbs) {
    const std::string enc = Base64Url::encode(tb.raw().data(), tb.raw().length());
    switch (tb.type()) {
    case PROVIDED_TOKEN_BINDING:
      headers.addCopy(SecHeaders::get().TokenBindingID.Provided, enc);
      break;
    case REFERRED_TOKEN_BINDING:
      headers.addCopy(SecHeaders::get().TokenBindingID.Referred, enc);
      break;
    default:
      headers.addCopy(SecHeaders::get().TokenBindingID.Other, enc);
      break;
    }
  }

  return Http::FilterHeadersStatus::Continue;
};

Http::FilterDataStatus TokenBindingFilter::decodeData(Buffer::Instance&, bool) {
  return Http::FilterDataStatus::Continue;
};

Http::FilterTrailersStatus TokenBindingFilter::decodeTrailers(Http::HeaderMap&) {
  return Http::FilterTrailersStatus::Continue;
};

void TokenBindingFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;
};

} // namespace TokenBinding
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
