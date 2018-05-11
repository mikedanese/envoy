#include "extensions/filters/http/tokbind/tokbind.h"
#include "common/common/logger.h"
#include "common/common/assert.h"

#include "openssl/bn.h"
#include "openssl/bytestring.h"
#include "openssl/ecdsa.h"
#include "openssl/ec_key.h"
#include "openssl/nid.h"
#include "openssl/sha.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TokenBinding {

namespace {

#define CHECK_CBS(expr)                                                                            \
  if (!CBS_##expr)                                                                                 \
    return false;

inline CBS string_view_as_cbs(absl::string_view str) {
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(str.data()), str.length());
  return cbs;
};

inline absl::string_view cbs_as_string_view(CBS cbs) {
  absl::string_view sv(reinterpret_cast<const char*>(CBS_data(&cbs)), CBS_len(&cbs));
  return sv;
};

}; // namespace

bool ParseTokenBindingMessage(const std::string& raw, std::vector<TokenBinding>& tbs) {
  CBS stbm = string_view_as_cbs(raw);

  CBS stb;
  CHECK_CBS(get_u16_length_prefixed(&stbm, &stb));

  while (CBS_len(&stb)) {
    TokenBinding tb;
    tb.Parse(&stb);
    tbs.push_back(tb);
  };

  ASSERT(!CBS_len(&stb));
  ASSERT(!CBS_len(&stbm));

  return true;
};

bool VerifyTokenBindings(std::vector<TokenBinding>& tbs, const std::string& ekm) {
  for (auto const& tb : tbs) {
    if (!tb.Verify(ekm))
      return false;
  }
  return true;
};

bool TokenBinding::Parse(CBS* stb) {
  CBS raw = *stb;
  uint8_t type;
  CHECK_CBS(get_u8(stb, &type));
  type_ = static_cast<TokenBindingType>(type);

  uint8_t key_param;
  CHECK_CBS(get_u8(stb, &key_param));
  key_parameters_ = static_cast<TokenBindingKeyParameters>(key_param);

  uint16_t key_len;
  CHECK_CBS(get_u16(stb, &key_len));

  CBS key;
  CHECK_CBS(get_bytes(stb, &key, key_len));
  public_key_ = cbs_as_string_view(key);

  CBS sig;
  CHECK_CBS(get_u16_length_prefixed(stb, &sig));
  sig_ = cbs_as_string_view(sig);

  // ignore extensions
  uint16_t ext_len;
  CHECK_CBS(get_u16(stb, &ext_len));
  CHECK_CBS(skip(stb, ext_len));

  raw.len -= CBS_len(stb);
  raw_ = cbs_as_string_view(raw);

  return true;
};

bool TokenBinding::Verify(absl::string_view ekm) const {
  const std::string& digest(Digest(ekm));

  switch (key_parameters_) {
  case ECDSAP256_SHA256: {
    return ECDSAVerify(digest);
  }
  case RSA2048_PKCS15_SHA256:
  case RSA2048_PSS_SHA256:
    return false;
  default:
    return false;
  };
};

bool TokenBinding::ECDSAVerify(absl::string_view digest) const {
  CBS ecpoints, xraw, yraw;

  CBS pub = string_view_as_cbs(public_key_);

  CHECK_CBS(get_u8_length_prefixed(&pub, &ecpoints));
  CHECK_CBS(get_bytes(&ecpoints, &xraw, 32));
  CHECK_CBS(get_bytes(&ecpoints, &yraw, 32));
  ASSERT(!CBS_len(&ecpoints));

  bssl::UniquePtr<BIGNUM> x(BN_bin2bn(CBS_data(&xraw), 32, NULL));
  bssl::UniquePtr<BIGNUM> y(BN_bin2bn(CBS_data(&yraw), 32, NULL));
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));

  EC_KEY_set_public_key_affine_coordinates(key.get(), x.get(), y.get());

  CBS sigraw, rraw, sraw;

  sigraw = string_view_as_cbs(sig_);
  CHECK_CBS(get_bytes(&sigraw, &rraw, 32));
  CHECK_CBS(get_bytes(&sigraw, &sraw, 32));
  ASSERT(!CBS_len(&sigraw));

  bssl::UniquePtr<BIGNUM> r(BN_bin2bn(CBS_data(&rraw), 32, NULL));
  bssl::UniquePtr<BIGNUM> s(BN_bin2bn(CBS_data(&sraw), 32, NULL));
  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
  ECDSA_SIG_set0(sig.get(), r.get(), s.get());

  return ECDSA_do_verify(reinterpret_cast<const uint8_t*>(digest.data()), SHA256_DIGEST_LENGTH,
                         sig.get(), key.get());
}

std::string TokenBinding::Digest(absl::string_view ekm) const {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, &type_, 1);
  SHA256_Update(&sha256, &key_parameters_, 1);
  SHA256_Update(&sha256, ekm.data(), ekm.length());
  SHA256_Final(digest, &sha256);
  std::string out(reinterpret_cast<char*>(&digest), SHA256_DIGEST_LENGTH);
  return out;
};

} // namespace TokenBinding
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
