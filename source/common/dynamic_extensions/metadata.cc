#include "source/common/dynamic_extensions/metadata.h"

#include <algorithm>
#include <ranges>
#include <span>
#include <elf.h>

#include "fmt/format.h"

using namespace std::literals;

absl::StatusOr<ExtensionMetadata> readExtensionMetadata(bytes_view extension_data) {
  if (extension_data.size() < sizeof(Elf64_Ehdr)) {
    return absl::InvalidArgumentError("file is not an ELF binary");
  }
  auto* header = reinterpret_cast<const Elf64_Ehdr*>(extension_data.data());
  if (header->e_ident[EI_MAG0] != ELFMAG0 ||
      header->e_ident[EI_MAG1] != ELFMAG1 ||
      header->e_ident[EI_MAG2] != ELFMAG2 ||
      header->e_ident[EI_MAG3] != ELFMAG3) {
    return absl::InvalidArgumentError("file is not an ELF binary");
  }

  if (header->e_ident[EI_CLASS] != ELFCLASS64 ||
      (header->e_machine != EM_X86_64 && header->e_machine != EM_AARCH64) ||
      header->e_version != EV_CURRENT) {
    return absl::InvalidArgumentError("ELF binary is not supported");
  }

  // read all section headers
  if (extension_data.size() < header->e_shoff + header->e_shnum * sizeof(Elf64_Shdr)) {
    return absl::InvalidArgumentError("failed to read section headers");
  }

  // read the section header name string table
  auto* strTabHdr = reinterpret_cast<const Elf64_Shdr*>(
    extension_data.subspan(header->e_shoff + header->e_shstrndx * sizeof(Elf64_Shdr)).first<sizeof(Elf64_Shdr)>().data());
  auto sectionNameStringTable = extension_data.subspan(strTabHdr->sh_offset).first(strTabHdr->sh_size);

  for (int shIdx = 0; shIdx < header->e_shnum; shIdx++) {
    auto* sectionHeader = reinterpret_cast<const Elf64_Shdr*>(
      extension_data.subspan(header->e_shoff + shIdx * sizeof(Elf64_Shdr)).first<sizeof(Elf64_Shdr)>().data());

    auto substr = sectionNameStringTable.subspan(sectionHeader->sh_name);
    auto sectionName = substr.first(std::distance(substr.begin(), std::find(substr.begin(), substr.end(), 0u)));
    if (sectionName != ".dx_metadata"_bv) {
      continue;
    }

    if (sectionHeader->sh_size > EXTENSION_METADATA_SIZE_MAX) {
      return absl::InvalidArgumentError(fmt::format("extension metadata section exceeds maximum size (%d > %d)",
                                                    sectionHeader->sh_size, EXTENSION_METADATA_SIZE_MAX));
    }
    if (extension_data.size() < sectionHeader->sh_offset + sectionHeader->sh_size) {
      return absl::InvalidArgumentError("failed to read metadata section");
    }
    auto rawMetadata = extension_data.subspan(sectionHeader->sh_offset).first(sectionHeader->sh_size);

    ExtensionMetadata md{};
    for (auto kv : rawMetadata | std::views::split(0u)) {
      if (kv.empty()) {
        continue;
      }
      auto eqIdx = std::distance(kv.begin(), std::find(kv.begin(), kv.end(), '='));
      auto key = to_string(bytes_view{kv}.first(eqIdx));
      auto value = to_string(bytes_view{kv}.subspan(eqIdx + 1));
      if (key == "id") {
        md.id = value;
      } else if (key == "license") {
        md.license = value;
      } else {
        md.unknown_keys[key] = value;
      }
    }
    return md;
  }

  return absl::InvalidArgumentError("extension metadata not found in file");
}
