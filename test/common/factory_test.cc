#include "source/common/factory.h"
#include "gtest/gtest.h"

using string_list = std::vector<std::string>;

namespace test {

class BaseTestObject {
public:
  virtual ~BaseTestObject() = default;

  BaseTestObject(int arg1, const std::string& arg2) {
    (void)arg1;
    (void)arg2;
  };

  virtual int number() = 0;
};

class BaseTestObjectFactory {
public:
  virtual ~BaseTestObjectFactory() = default;
  virtual std::vector<std::pair<std::string, priority_t>> names() const = 0;
  virtual std::unique_ptr<BaseTestObject> create(int arg1, const std::string& arg2) = 0;
};

class SpecificTestObject1 : public BaseTestObject {
public:
  SpecificTestObject1(int arg1, const std::string& arg2)
      : BaseTestObject(arg1, arg2) {};

  int number() override { return 1; }
};

class SpecificTestObjectFactory1 : public BaseTestObjectFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{"specific1", 0}, {"specific1@openssh.com", 0}};
  }
  std::unique_ptr<BaseTestObject> create(int arg1, const std::string& arg2) override {
    return std::make_unique<SpecificTestObject1>(arg1, arg2);
  };
};

class SpecificTestObject2 : public BaseTestObject {
public:
  SpecificTestObject2(int arg1, const std::string& arg2)
      : BaseTestObject(arg1, arg2) {};

  int number() override { return 2; }
};

class SpecificTestObjectFactory2 : public BaseTestObjectFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{"specific2", 1}};
  }
  std::unique_ptr<BaseTestObject> create(int arg1, const std::string& arg2) override {
    return std::make_unique<SpecificTestObject2>(arg1, arg2);
  };
};

class SpecificTestObject3 : public BaseTestObject {
public:
  SpecificTestObject3(int arg1, const std::string& arg2)
      : BaseTestObject(arg1, arg2) {};

  int number() override { return 3; }
};

class SpecificTestObjectFactory3 : public BaseTestObjectFactory {
public:
  std::vector<std::pair<std::string, priority_t>> names() const override {
    return {{"specific3@openssh.com", 3}, {"specific3", 2}}; // note: reverse order
  }
  std::unique_ptr<BaseTestObject> create(int arg1, const std::string& arg2) override {
    return std::make_unique<SpecificTestObject3>(arg1, arg2);
  };
};

using TestObjectFactoryRegistry = PriorityAwareFactoryRegistry<BaseTestObjectFactory,
                                                               BaseTestObject,
                                                               int, const std::string&>;

TEST(FactoryTest, NamesByPriority) {
  TestObjectFactoryRegistry r;
  r.registerType<SpecificTestObjectFactory1>();
  auto expected = string_list{"specific1", "specific1@openssh.com"};
  EXPECT_EQ(expected, r.namesByPriority());

  r.registerType<SpecificTestObjectFactory2>();
  expected = string_list{"specific1", "specific1@openssh.com", "specific2"};
  EXPECT_EQ(expected, r.namesByPriority());

  r.registerType<SpecificTestObjectFactory3>();
  expected = string_list{"specific1", "specific1@openssh.com", "specific2", "specific3", "specific3@openssh.com"};
  EXPECT_EQ(expected, r.namesByPriority());
}

TEST(FactoryTest, NamesByPriority_Reverse) {
  TestObjectFactoryRegistry r;
  r.registerType<SpecificTestObjectFactory3>();
  auto expected = string_list{"specific3", "specific3@openssh.com"};
  EXPECT_EQ(expected, r.namesByPriority());

  r.registerType<SpecificTestObjectFactory2>();
  expected = string_list{"specific2", "specific3", "specific3@openssh.com"};
  EXPECT_EQ(expected, r.namesByPriority());

  r.registerType<SpecificTestObjectFactory1>();
  expected = string_list{"specific1", "specific1@openssh.com", "specific2", "specific3", "specific3@openssh.com"};
  EXPECT_EQ(expected, r.namesByPriority());
}

TEST(FactoryTest, FactoryForName) {
  TestObjectFactoryRegistry r;
  r.registerType<SpecificTestObjectFactory1>();
  r.registerType<SpecificTestObjectFactory2>();
  r.registerType<SpecificTestObjectFactory3>();

  for (auto [name, number] : std::vector<std::tuple<std::string, int>>{
         {"specific1", 1},
         {"specific1@openssh.com", 1},
         {"specific2", 2},
         {"specific3", 3},
         {"specific3@openssh.com", 3},
       }) {
    auto f = r.factoryForName(name);
    auto obj = f->create(0, "");
    EXPECT_EQ(number, obj->number());
  }
}

} // namespace test