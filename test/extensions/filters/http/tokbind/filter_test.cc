#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "extensions/filters/http/tokbind/tokbind.h"
#include "common/common/base64.h"

using testing::_;
using testing::Eq;
using testing::Not;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TokenBinding {

using ::testing::Eq; // Optional ::testing aliases. Remove if unused.

struct parse_and_verify {
  std::string ekm;
  std::string stbm;
};

TEST(TokenBindingFilterTest, ParseAndVerify) {
  std::vector<parse_and_verify> cs = {
      {
          "7LsNP3BT1aHHdXdk6meEWjtSkiPVLb7YS6iHp-JXmuE",
          "AIkAAgBBQLgtRpWFPN66kxhxGrtaKrzcMtHw7HV8yMk_-"
          "MdRXJXbDMYxZCWnCASRRrmHHHL5wmpP3bhYt0ChRDbsMapfh_QAQN1He3Ftj4Wa_S_"
          "fzZVns4saLfj6aBoMSQW6rLs19IIvHze7LrGjKyCfPTKXjajebxp-TLPFZCc0JTqTY5_0MBAAAA",
      },
      {
          "4jTc5e1QpocqPTZ5l6jsb6pRP18IFKdwwPvasYjn1-E",
          "ARIAAgBBQJFXJir2w4gbJ7grBx9uTYWIrs9V50-PW4ZijegQ0LUM-_bGnGT6DizxUK-"
          "m5n3dQUIkeH7ybn6wb1C5dGyV_IAAQDDFToFrHt41Zppq7u_SEMF_E-KimAB-"
          "HewWl2MvZzAQ9QKoWiJCLFiCkjgtr1RrA2-"
          "jaJvoB8o51DTGXQydWYkAAAECAEFAuC1GlYU83rqTGHEau1oqvNwy0fDsdXzIyT_"
          "4x1FcldsMxjFkJacIBJFGuYcccvnCak_duFi3QKFENuwxql-"
          "H9ABAMcU7IjJOUA4IyE6YoEcfz9BMPQqwM5M6hw4RZNQd58fsTCCslQE_NmNCl9JXy4NkdkEZBxqvZGPr0y8QZ_"
          "bmAwAA",
      },
      {
          "1mOiLC0IFA5SMBQQVvd48VSKNuF89USGw2_UBbWik34",
          "AIkAAgBBQKzyIrmcY_YCtHVoSHBut69vrGfFdy1_"
          "YKTZfFJv6BjrZsKD9b9FRzSBxDs1twTqnAS71M1RBumuihhI9xqxXKkAQIMi9gthwFtmF1lpXioRsIlQA8vZOKQ0"
          "hrJE1_610h0h-IX-O_WllivUBoyLV7ypArE15whKaDrfwsolflmWfPsAAA",
      },
      {
          "r4FNRMOUG_0gQQKyDGwEiCE6v8lmpsV99GZddteFIYQ",
          "ARIAAgBBQCfsI1D1sTq5mvT_2H_dihNIvuHJCHGjHPJchPavNbGrOo26-2JgT_IsbvZd4daDFbirYBIwJ-"
          "TK1rh8FzrC-psAQO4Au9xPupLSkhwT9Yn9aSvHXFsMLh4d4cEBKGP1clJtsfUFGDw-"
          "8HQSKwgKFN3WfZGq27y8NB3NAM1oNzvqVOIAAAECAEFArPIiuZxj9gK0dWhIcG63r2-sZ8V3LX9gpNl8Um_"
          "oGOtmwoP1v0VHNIHEOzW3BOqcBLvUzVEG6a6KGEj3GrFcqQBA9YxqHPBIuDui_aQ1SoRGKyBEhaG2i-"
          "Wke3erRb1YwC7nTgrpqqJG3z1P8bt7cjZN6TpOyktdSSK7OJgiApwG7AAA",
      },
  };

  for (auto const& c : cs) {
    std::string stbraw(Base64Url::decode(c.stbm));
    EXPECT_THAT(stbraw, Not(Eq("")));

    std::vector<TokenBinding> tbs;
    EXPECT_TRUE(ParseTokenBindingMessage(stbraw, tbs));

    const std::string& ekmraw(Base64Url::decode(c.ekm));
    EXPECT_THAT(ekmraw, Not(Eq("")));
    EXPECT_TRUE(VerifyTokenBindings(tbs, ekmraw));
  }
}

class TokenBindingFilterTest : public testing::Test {
protected:
  TokenBindingFilterTest() {}
};

} // namespace TokenBinding
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
