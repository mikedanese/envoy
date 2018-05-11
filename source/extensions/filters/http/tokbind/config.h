#pragma once

#include "envoy/config/filter/http/squash/v2/squash.pb.h"

#include "extensions/filters/http/common/factory_base.h"
#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace TokenBinding {

/**
 * Config registration for the squash filter. @see NamedHttpFilterConfigFactory.
 */
class TokenBindingFilterConfigFactory : public NamedHttpFilterConfigFactory {
public:
  HttpFilterFactoryCb createFilterFactory(const Json::Object&, const std::string&,
                                          FactoryContext&) override {
    return [](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      callbacks.addStreamDecoderFilter(
          Http::StreamDecoderFilterSharedPtr{new gke::FrontProxyFilter()});
    };
  }

  HttpFilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message&, const std::string&,
                                                   FactoryContext&) override {
    return [](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      callbacks.addStreamDecoderFilter(
          Http::StreamDecoderFilterSharedPtr{new gke::FrontProxyFilter()});
    };
  };

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new Envoy::ProtobufWkt::Empty()};
  };

  std::string name() override { return "gke_front_proxy"; }
};

static Registry::RegisterFactory<gke::FrontProxyFilterConfig, NamedHttpFilterConfigFactory>
    register_;
} // namespace TokenBinding
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
