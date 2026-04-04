#include <elf.h>
#include <exception>
#include <fcntl.h>
#include <iterator>
#include <sys/stat.h>
#include <sys/mman.h>
#include <cxxabi.h>

#include "fmt/format.h"
#include "argparse/argparse.hpp"

#include "source/common/dynamic_extensions/metadata.h"
#include "source/common/status.h"
#include "source/common/types.h"

using namespace std::literals;

struct MmapFileHandle {
  MmapFileHandle(const std::string& filename, void* addr, struct stat info)
      : filename_(filename), addr_(addr), info_(info) {}

  ~MmapFileHandle() { munmap(addr_, info_.st_size); }

  MmapFileHandle(MmapFileHandle&&) = delete;
  MmapFileHandle(const MmapFileHandle&) = delete;
  MmapFileHandle& operator=(const MmapFileHandle&) = delete;
  MmapFileHandle& operator=(MmapFileHandle&&) = delete;

  bytes_view view() const {
    return {reinterpret_cast<const uint8_t*>(addr_), static_cast<size_t>(info_.st_size)};
  }

  std::string filename_;
  void* addr_;
  const struct stat info_;
};

absl::StatusOr<std::unique_ptr<MmapFileHandle>> mmapFile(const std::string& filename) {
  auto fd = open(filename.c_str(), O_RDONLY);
  if (fd == -1) {
    return absl::ErrnoToStatus(errno, fmt::format("error opening file: {}", filename));
  }
  struct stat info;
  if (fstat(fd, &info) == -1) {
    close(fd);
    return absl::ErrnoToStatus(errno, "stat failed");
  }
  auto* addr = mmap(nullptr, info.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (addr == MAP_FAILED) {
    close(fd);
    return absl::ErrnoToStatus(errno, "mmap failed");
  }
  close(fd);
  return std::make_unique<MmapFileHandle>(filename, addr, info);
}

struct SymbolTableView {
  SymbolTableView() = default;
  SymbolTableView(const SymbolTableView&) = delete;
  SymbolTableView(SymbolTableView&&) = default;
  SymbolTableView& operator=(const SymbolTableView&) = delete;
  SymbolTableView& operator=(SymbolTableView&&) = default;

  std::vector<std::tuple<std::string_view, const Elf64_Sym*>> items; // keys are null-terminated
};

enum class Filter {
  Undefined = 1,
  Defined = 2,
};

constexpr Filter operator|(Filter lhs, Filter rhs) {
  return static_cast<Filter>(std::to_underlying(lhs) | std::to_underlying(rhs));
}

constexpr Filter operator&(Filter lhs, Filter rhs) {
  return static_cast<Filter>(std::to_underlying(lhs) & std::to_underlying(rhs));
}

bool flag_demangle;

absl::StatusOr<SymbolTableView> readDynamicSymbols(const MmapFileHandle& f, Filter filter) {
  if (f.info_.st_size < sizeof(Elf64_Ehdr)) {
    return absl::InvalidArgumentError("file is not an ELF binary");
  }
  auto* header = reinterpret_cast<const Elf64_Ehdr*>(f.addr_);
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
  if (f.info_.st_size < header->e_shoff + header->e_shnum * sizeof(Elf64_Shdr)) {
    return absl::InvalidArgumentError("failed to read section headers");
  }

  bool showUndefined = (filter & Filter::Undefined) == Filter::Undefined;
  bool showDefined = (filter & Filter::Defined) == Filter::Defined;

  auto extension_data = f.view();

  const Elf64_Shdr* sh_dynamic{};
  const Elf64_Shdr* sh_dynsym{};
  const Elf64_Shdr* sh_gnu_versym{};  // .gnu.version
  const Elf64_Shdr* sh_gnu_verdef{};  // .gnu.version_d
  const Elf64_Shdr* sh_gnu_verneed{}; // .gnu.version_r

  for (int shIdx = 0; shIdx < header->e_shnum; shIdx++) {
    auto* sectionHeader = reinterpret_cast<const Elf64_Shdr*>(
      extension_data.subspan(header->e_shoff + shIdx * sizeof(Elf64_Shdr), sizeof(Elf64_Shdr)).data());

    switch (sectionHeader->sh_type) {
    case SHT_DYNAMIC:
      sh_dynamic = sectionHeader;
      break;
    case SHT_DYNSYM:
      sh_dynsym = sectionHeader;
      break;
    case SHT_GNU_versym:
      sh_gnu_versym = sectionHeader;
      break;
    case SHT_GNU_verdef:
      sh_gnu_verdef = sectionHeader;
      break;
    case SHT_GNU_verneed:
      sh_gnu_verneed = sectionHeader;
      break;
    default:
      continue;
    }
  }
  if (sh_dynamic == nullptr) {
    return absl::InvalidArgumentError("file is missing section: .dynamic");
  }
  if (sh_dynsym == nullptr) {
    return absl::InvalidArgumentError("file is missing section: .dynsym");
  }
  if (sh_gnu_versym == nullptr) {
    return absl::InvalidArgumentError("file is missing section: .gnu.version");
  }
  if (sh_gnu_verdef == nullptr) {
    return absl::InvalidArgumentError("file is missing section: .gnu.version_d");
  }
  if (sh_gnu_verneed == nullptr) {
    return absl::InvalidArgumentError("file is missing section: .gnu.version_r");
  }

  // Find version requirements in .dynamic
  {
    Elf64_Xword verdefnum{};
    Elf64_Xword verneednum{};
    auto dynamicEntries = extension_data.subspan(sh_dynamic->sh_offset, sh_dynamic->sh_size);
    while (!dynamicEntries.empty()) {
      auto* entry = reinterpret_cast<const Elf64_Dyn*>(dynamicEntries.data());
      switch (entry->d_tag) {
      case DT_VERDEF:
      case DT_VERDEFNUM:
        verdefnum = entry->d_un.d_val;
        break;
      case DT_VERNEED:
      case DT_VERNEEDNUM:
        verneednum = entry->d_un.d_val;
        break;
      }
      dynamicEntries = dynamicEntries.subspan(sizeof(Elf64_Dyn));
    }

    auto* versionStrTabHdr = reinterpret_cast<const Elf64_Shdr*>(
      extension_data.subspan(header->e_shoff + sh_gnu_verdef->sh_link * sizeof(Elf64_Shdr), sizeof(Elf64_Shdr)).data());
    auto versionStrTable = extension_data.subspan(versionStrTabHdr->sh_offset, versionStrTabHdr->sh_size);
    auto verdefEntries = extension_data.subspan(sh_gnu_verdef->sh_offset, sh_gnu_verdef->sh_size);
    for (auto i = 0; i < verdefnum; i++) {
      auto* entry = reinterpret_cast<const Elf64_Verdef*>(
        verdefEntries.subspan(i * sizeof(Elf64_Verdef), sizeof(Elf64_Verdef)).data());
    }
  }

  //

  SymbolTableView out;

  auto* symbolStrTabHdr = reinterpret_cast<const Elf64_Shdr*>(
    extension_data.subspan(header->e_shoff + sh_dynsym->sh_link * sizeof(Elf64_Shdr), sizeof(Elf64_Shdr)).data());
  auto symbolStringTable = extension_data.subspan(symbolStrTabHdr->sh_offset, symbolStrTabHdr->sh_size);

  auto dynsymEntries = extension_data.subspan(sh_dynsym->sh_offset, sh_dynsym->sh_size);
  out.items.reserve(out.items.size() + (dynsymEntries.size() / sizeof(Elf64_Sym)));
  while (!dynsymEntries.empty()) {
    auto* sym = reinterpret_cast<const Elf64_Sym*>(dynsymEntries.data());
    if (sym->st_name != 0) {
      bool isUndefined = sym->st_shndx == SHN_UNDEF;
      if ((isUndefined && showUndefined) || (!isUndefined && showDefined)) {
        auto symName = symbolStringTable.subspan(sym->st_name);
        auto name = to_string_view(symName.first(std::distance(symName.begin(), std::next(std::find(symName.begin(), symName.end(), 0u)))));
        out.items.emplace_back(name, sym);
      }
    }
    dynsymEntries = dynsymEntries.subspan(sizeof(Elf64_Sym));
  }

  std::sort(out.items.begin(), out.items.end(), [](const auto& a, const auto& b) {
    return std::get<0>(a) < std::get<0>(b);
  });

  return std::move(out);
}

absl::Status printMetadata(const MmapFileHandle& f) {
  auto res = readExtensionMetadata(f.view());
  if (!res.ok()) {
    return absl::InvalidArgumentError(fmt::format("error reading metadata: {}", res.status().message()));
  }
  fmt::println("Extension ID: {}", res->id);
  fmt::println("License:      {}", res->license);
  if (!res->unknown_keys.empty()) {
    fmt::println("Unknown Keys:");
    for (const auto& [k, v] : res->unknown_keys) {
      fmt::println("  {}: {}", k, v);
    }
  }
  return absl::OkStatus();
}

absl::Status printDynamicSymbols(const MmapFileHandle& f, Filter filter) {
  auto dst = readDynamicSymbols(f, filter);
  if (!dst.ok()) {
    return dst.status();
  }
  if (flag_demangle) {
    char* buf{};
    size_t len = 0;
    for (const auto& [k, v] : dst->items) {
      int status{};
      buf = abi::__cxa_demangle(k.data(), buf, &len, &status); // NOLINT:bugprone-suspicious-stringview-data-usage
      switch (status) {
      case 0:
        std::cout << buf << "\n";
        break;
      case -2:
        std::cout << k.data() << "\n";
        break;
      default:
        free(buf);
        return absl::InternalError(fmt::format("__cxa_demangle error {}", status));
      }
    }
    free(buf);
    std::cout.flush();
  } else {
    for (const auto& [k, v] : dst->items) {
      std::cout << k.data() << "\n";
    }
    std::cout.flush();
  }
  return absl::OkStatus();
}

absl::Status checkCompatibility(const MmapFileHandle& host, const MmapFileHandle& ext) {
  auto extUndefined = readDynamicSymbols(ext, Filter::Undefined);
  if (!extUndefined.ok()) {
    return extUndefined.status();
  }

  auto hostDefined = readDynamicSymbols(host, Filter::Defined);
  if (!hostDefined.ok()) {
    return hostDefined.status();
  }
}

int main(int argc, char** argv) {
  argparse::ArgumentParser cmd("read-extension");
  auto& modes = cmd.add_mutually_exclusive_group(true);
  modes.add_argument("-m", "--metadata")
    .help("Print extension metadata")
    .flag();

  modes.add_argument("-s", "--symbols")
    .help("Print symbols in the extension's dynamic symbol table")
    .implicit_value("undefined"s)
    .choices("undefined"s, "defined"s, "all"s);

  modes.add_argument("-c", "--check")
    .help("Check if the extension is compatible with the given binary")
    .nargs(1)
    .flag();

  cmd.add_argument("-d", "--demangle")
    .help("Demangle C++ symbols when printing them")
    .flag();

  cmd.add_argument("filename")
    .nargs(1)
    .required()
    .help("Path to an extension binary");

  try {
    cmd.parse_args(argc, argv);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return 1;
  }

  auto filename = cmd.get("filename");
  auto stat = [&] {
    auto f = mmapFile(filename);
    if (!f.ok()) {
      return f.status();
    }
    if (cmd.is_used("metadata")) {
      return printMetadata(**f);
    } else if (cmd.is_used("symbols")) {
      Filter filter{};
      auto symbolsMode = cmd.get("symbols");
      if (symbolsMode == "undefined") {
        filter = Filter::Undefined;
      } else if (symbolsMode == "defined") {
        filter = Filter::Defined;
      } else if (symbolsMode == "all") {
        filter = Filter::Undefined | Filter::Defined;
      }
      return printDynamicSymbols(**f, filter);
    } else if (cmd.is_used("check")) {
      auto host = mmapFile(filename);
      if (!host.ok()) {
        return host.status();
      }
      return checkCompatibility(**host, **f);
    }
    return absl::OkStatus();
  }();

  if (!stat.ok()) {
    std::cerr << fmt::format("{}: {}", filename, statusToString(stat)) << std::endl;
    return 1;
  }
  return 0;
}