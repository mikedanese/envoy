#pragma once

#include "common/singleton/const_singleton.h"
#include "envoy/http/header_map.h"

#include "absl/strings/string_view.h"
#include "openssl/bytestring.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TokenBinding {

enum TokenBindingType {
  PROVIDED_TOKEN_BINDING = 0,
  REFERRED_TOKEN_BINDING = 1,
};

enum TokenBindingKeyParameters {
  RSA2048_PKCS15_SHA256 = 0,
  RSA2048_PSS_SHA256 = 1,
  ECDSAP256_SHA256 = 2,
};

class TokenBinding {
public:
  TokenBinding(){};

  bool Verify(absl::string_view ekm) const;

  bool Parse(CBS* stb);

  TokenBindingType type() const { return type_; };
  absl::string_view raw() const { return raw_; };

private:
  TokenBindingType type_;
  TokenBindingKeyParameters key_parameters_;
  absl::string_view public_key_;
  absl::string_view sig_;
  absl::string_view raw_;

  std::string Digest(absl::string_view ekm) const;
  bool ECDSAVerify(absl::string_view digest) const;
};

bool ParseTokenBindingMessage(const std::string& raw, std::vector<TokenBinding>& tbs);

bool VerifyTokenBindings(std::vector<TokenBinding>& tbs, const std::string& ekm);

} // namespace TokenBinding
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
