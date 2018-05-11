licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "tokbind_filter_lib",
    srcs = ["filter.cc"],
    hdrs = ["filter.h"],
    deps = [
        ":tokbind_lib",
        "//include/envoy/http:filter_interface",
        "//source/common/common:base64_lib",
        "//source/common/http:header_map_lib",
        "//source/common/http:utility_lib",
    ],
)

envoy_cc_library(
    name = "tokbind_lib",
    srcs = ["tokbind.cc"],
    hdrs = ["tokbind.h"],
    external_deps = [
        "ssl",
    ],
    deps = [
        "//source/common/http:header_map_lib",
    ],
)

envoy_cc_library(
    name = "config",
    hdrs = ["config.h"],
    deps = [
        "//include/envoy/registry",
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:factory_base_lib",
        "//source/extensions/filters/http/gzip:gzip_filter_lib",
    ],
)
