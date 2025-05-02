#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <vector>
#include <ranges>
#include "fmt/format.h"

#pragma clang unsafe_buffer_usage begin
#include "source/common/common/assert.h"
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
      RELEASE_ASSERT(!factories_.contains(name), fmt::format("name already registered: {}", name));
      factories_[name] = [] { return std::make_unique<Derived>(); };
      priorities_.emplace(priority, name);
    }
  }

  std::unique_ptr<F> factoryForName(const std::string& name) {
    RELEASE_ASSERT(factories_.contains(name), fmt::format("no factory for name: {}", name));
    return factories_[name]();
  }

  std::vector<std::string> namesByPriority() {
    return priorities_ | std::views::values | std::ranges::to<std::vector>();
  }

private:
  std::unordered_map<std::string, std::function<std::unique_ptr<F>()>> factories_;
  std::multimap<priority_t, std::string, std::less<priority_t>> priorities_;
};
