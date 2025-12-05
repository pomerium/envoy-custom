#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <vector>
#include <ranges>
#include "fmt/format.h"

#pragma clang unsafe_buffer_usage begin
#include "envoy/common/exception.h"
#pragma clang unsafe_buffer_usage end

// algorithm priority index (0 is highest priority)
using priority_t = uint32_t;

template <typename F, typename T, typename... Args>
concept Factory = requires(F f, Args... args) {
  { f.names() } -> std::same_as<std::vector<std::pair<std::string, priority_t>>>;
  { f.create(args...) } -> std::same_as<std::unique_ptr<T>>;
};

template <typename F, typename T, typename... Args>
  requires Factory<F, T, Args...>
class PriorityAwareFactoryRegistry {
public:
  template <typename Derived>
    requires std::derived_from<Derived, F>
  void registerType() {
    Derived factory;
    for (const auto& [name, priority] : factory.names()) {
      if (factories_.contains(name)) {
        throw Envoy::EnvoyException(fmt::format("name already registered: {}", name));
      }
      factories_[name] = [] { return std::make_unique<Derived>(); };
      priorities_.emplace(priority, name);
    }
  }

  // Set a list of names (reported by F::names()) to treat as not found, even if registered to
  // the factory. The names do not necessarily need to exist in the factory.
  // Masked names will be filtered out of the list returned by namesByPriority(), and factoryForName
  // will throw as if the factory for that name was not found.
  // Note that if a factory reports more than one name from F::names(), *all* of those names must
  // be masked for the factory to be completely disabled.
  void setMaskedNames(const std::vector<std::string>& names) {
    masked_names_.clear();
    masked_names_.insert(names.begin(), names.end());
  }

  std::unique_ptr<F> factoryForName(const std::string& name) {
    if (!factories_.contains(name) || masked_names_.contains(name)) {
      throw Envoy::EnvoyException(fmt::format("no factory for name: {}", name));
    }
    return factories_[name]();
  }

  std::vector<std::string> namesByPriority() {
    return priorities_ |
           std::views::values |
           std::views::filter([this](const std::string& name) {
             return !masked_names_.contains(name);
           }) |
           std::ranges::to<std::vector>();
  }

private:
  absl::flat_hash_map<std::string, std::function<std::unique_ptr<F>()>> factories_;
  std::multimap<priority_t, std::string, std::less<priority_t>> priorities_;
  absl::flat_hash_set<std::string> masked_names_;
};
