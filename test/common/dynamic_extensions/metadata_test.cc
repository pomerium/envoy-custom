#include "source/common/dynamic_extensions/metadata.h"
#include "source/common/types.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <array>
#include <elf.h>

using namespace std::literals;

Elf64_Ehdr defaultHeader() {
  Elf64_Ehdr hdr{};
  hdr.e_ident[EI_MAG0] = ELFMAG0;
  hdr.e_ident[EI_MAG1] = ELFMAG1;
  hdr.e_ident[EI_MAG2] = ELFMAG2;
  hdr.e_ident[EI_MAG3] = ELFMAG3;
  hdr.e_ident[EI_CLASS] = ELFCLASS64;
  hdr.e_ident[EI_DATA] = ELFDATA2LSB;
  hdr.e_ident[EI_VERSION] = EV_CURRENT;
  hdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
  hdr.e_ident[EI_ABIVERSION] = 0;

  hdr.e_type = ET_DYN;
  hdr.e_machine = EM_X86_64;
  hdr.e_version = EV_CURRENT;
  hdr.e_entry = 0;
  hdr.e_phoff = 64;
  hdr.e_shoff = 64;
  hdr.e_flags = 0;
  hdr.e_ehsize = 64;
  hdr.e_phentsize = 56;
  hdr.e_phnum = 0;
  hdr.e_shentsize = 64;
  hdr.e_shnum = 0;
  hdr.e_shstrndx = 0;
  return hdr;
}

TEST(MetadataTest, InvalidFileFormat) {
  std::array<uint8_t, 63> short_read;
  EXPECT_EQ(absl::InvalidArgumentError("file is not an ELF binary"),
            readExtensionMetadata(short_read).status());

  std::vector<std::array<uint8_t, 64>> invalid_magic{{
    {""},
    {"\177"},
    {"\177E"},
    {"\177EL"},
    {"\176ELF"},
    {"\177eLF"},
    {"\177ElF"},
    {"\177ELf"},
  }};

  for (const auto& hdr : invalid_magic) {
    EXPECT_EQ(absl::InvalidArgumentError("file is not an ELF binary"),
              readExtensionMetadata(hdr).status());
  }

  const auto hdr = defaultHeader();

  std::vector<Elf64_Ehdr> valid_headers;
  std::vector<Elf64_Ehdr> unsupported_headers;
  std::vector<Elf64_Ehdr> invalid_headers;

  valid_headers.push_back(hdr);
  {
    Elf64_Ehdr copy = hdr;
    copy.e_machine = EM_AARCH64;
    valid_headers.push_back(copy);
  }

  {
    Elf64_Ehdr copy = hdr;
    copy.e_ident[EI_CLASS] = ELFCLASS32;
    unsupported_headers.push_back(copy);
  }
  {
    Elf64_Ehdr copy = hdr;
    copy.e_machine = EM_PPC;
    unsupported_headers.push_back(copy);
  }
  {
    Elf64_Ehdr copy = hdr;
    copy.e_version = EV_NONE;
    unsupported_headers.push_back(copy);
  }

  for (auto hdr : valid_headers) {
    auto hdrBytes = std::bit_cast<std::array<uint8_t, sizeof(hdr)>>(hdr);
    EXPECT_EQ(absl::InvalidArgumentError("failed to read section headers"),
              readExtensionMetadata(hdrBytes).status());
  }

  for (auto hdr : unsupported_headers) {
    auto hdrBytes = std::bit_cast<std::array<uint8_t, sizeof(hdr)>>(hdr);
    EXPECT_EQ(absl::InvalidArgumentError("extension was built for an unsupported architecture"),
              readExtensionMetadata(hdrBytes).status());
  }

  for (auto hdr : invalid_headers) {
    auto hdrBytes = std::bit_cast<std::array<uint8_t, sizeof(hdr)>>(hdr);
    EXPECT_EQ(absl::InvalidArgumentError("file is not an ELF binary"),
              readExtensionMetadata(hdrBytes).status());
  }
}

TEST(MetadataTest, ReadMetadata) {
  struct elf {
    Elf64_Ehdr ehdr{};

    Elf64_Phdr phdr_unused{};

    Elf64_Shdr sh_null{};
    Elf64_Shdr sh_shstrtab{};
    Elf64_Shdr sh_dx_metadata{};

    std::array<char, 32> shstrtab{"\0.shstrtab\0.dx_metadata"};
    std::array<char, 56> dx_metadata{"id=test-extension\0license=Apache-2.0\0foo=bar\0bar=baz"};
  };

  Elf64_Ehdr hdr = defaultHeader();

  hdr.e_shnum = 3;
  hdr.e_shstrndx = 1;
  hdr.e_phnum = 1;
  hdr.e_phoff = offsetof(elf, phdr_unused);
  hdr.e_shoff = offsetof(elf, sh_null);

  auto e = elf{};
  e.ehdr = hdr;

  e.sh_shstrtab.sh_name = 1; // offset within shstrtab
  e.sh_shstrtab.sh_type = SHT_STRTAB;
  e.sh_shstrtab.sh_offset = offsetof(elf, shstrtab);
  e.sh_shstrtab.sh_size = sizeof(elf::shstrtab);
  e.sh_shstrtab.sh_addralign = 1; // chars

  e.sh_dx_metadata.sh_name = 11;
  e.sh_dx_metadata.sh_type = SHT_PROGBITS;
  e.sh_dx_metadata.sh_flags = SHF_ALLOC;
  e.sh_dx_metadata.sh_addr = offsetof(elf, dx_metadata);
  e.sh_dx_metadata.sh_offset = offsetof(elf, dx_metadata);
  e.sh_dx_metadata.sh_size = sizeof(elf::dx_metadata);
  e.sh_dx_metadata.sh_addralign = 1;

  {
    auto data = std::bit_cast<std::array<uint8_t, sizeof(elf)>>(e);
    auto md = readExtensionMetadata(data);
    ASSERT_TRUE(md.ok());
    EXPECT_EQ("test-extension"s, md->id);
    EXPECT_EQ("Apache-2.0"s, md->license);

    auto unknownKeys = std::unordered_map<std::string, std::string>{
      {"foo", "bar"},
      {"bar", "baz"},
    };
    EXPECT_EQ(unknownKeys, md->unknown_keys);
  }

  {
    auto copy = e;
    copy.sh_dx_metadata.sh_size = EXTENSION_METADATA_SIZE_MAX + 1;
    auto data = std::bit_cast<std::array<uint8_t, sizeof(elf)>>(copy);
    auto md = readExtensionMetadata(data);
    ASSERT_THAT(md.status().message(), testing::HasSubstr("extension metadata section exceeds maximum size"));
  }

  {
    auto copy = e;
    copy.sh_dx_metadata.sh_offset = sizeof(copy) + 1;
    auto data = std::bit_cast<std::array<uint8_t, sizeof(elf)>>(copy);
    auto md = readExtensionMetadata(data);
    ASSERT_THAT(md.status().message(), testing::HasSubstr("failed to read metadata section"));
  }

  {
    auto copy = e;
    std::array<char, 56> metadataWithEmptySections{"\0id=test\0\0\0\0\0license=Apache-2.0\0\0foo=bar\0\0"};
    copy.dx_metadata.swap(metadataWithEmptySections);

    auto data = std::bit_cast<std::array<uint8_t, sizeof(elf)>>(copy);
    auto md = readExtensionMetadata(data);
    ASSERT_TRUE(md.ok());
    EXPECT_EQ("test"s, md->id);
    EXPECT_EQ("Apache-2.0"s, md->license);

    auto unknownKeys = std::unordered_map<std::string, std::string>{
      {"foo", "bar"},
    };
    EXPECT_EQ(unknownKeys, md->unknown_keys);
  }
}