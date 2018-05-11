licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

envoy_package()

envoy_extension_cc_test(
    name = "tokbind_filter_test",
    srcs = ["filter_test.cc"],
    extension_name = "envoy.filters.http.tokbind",
    deps = [
        "//source/common/http:header_map_lib",
        "//source/extensions/filters/http/tokbind:tokbind_filter_lib",
        "//test/mocks/buffer:buffer_mocks",
        "//test/mocks/http:http_mocks",
        "//test/mocks/upstream:upstream_mocks",
    ],
)
