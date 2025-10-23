#include <gtest/gtest.h>

// You can include headers from your qlogging_lib here to test your code.
// For example:
// #include "parser.h"
// #include "keyUtils.h"

// A simple test case to verify that the test framework is set up correctly.
TEST(SanityCheck, BasicAssertion) {
    // This test checks if 2 equals 2, which should always pass.
    // It's a good way to confirm that your test executable compiles and runs.
    EXPECT_EQ(2, 2);
}

// Example of a disabled test. It won't be run by default.
TEST(ExampleTests, DISABLED_TrivialTest) {
    EXPECT_TRUE(true);
}

// You can add more tests for your library components here.
// For example, to test a function from 'parser.h':
/*
TEST(ParserTest, HandlesEmptyInput) {
    Parser myParser;
    auto result = myParser.parse("");
    EXPECT_FALSE(result.has_value());
}
*/

// The main() function for running the tests is provided by the gtest_main
// library that you linked in your CMakeLists.txt, so you don't need to
// write it yourself.