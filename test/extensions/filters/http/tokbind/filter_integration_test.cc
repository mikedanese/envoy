#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace {

using ::testing::Eq; // Optional ::testing aliases. Remove if unused.

TEST(FilterIntegrationTest, DoesFoo) {
  EXPECT_THAT(1, Eq(2)); // Obvious failure, for educational purposes only.
}

class FilterIntegrationTest : public testing::Test {
protected:
  FilterIntegrationTest() {}
};

TEST_F(FilterIntegrationTest, HasPropertyBar) {
  EXPECT_THAT(1, Eq(2)); // Obvious failure, for educational purposes only.
}

} // namespace
