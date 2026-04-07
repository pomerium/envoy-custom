#include <elf.h>
#include <exception>
#include <fcntl.h>
#include <iterator>
#include <sys/stat.h>
#include <sys/mman.h>
#include <cxxabi.h>
#include <unordered_map>

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

struct SymbolInfo {
  size_t index;
  const Elf64_Sym* symbol;
  Elf64_Half version_id;
};

struct VersionNeededInfo {
  std::string_view version;
  std::string_view file;
};

struct SymbolVersionsCache {
  std::unordered_map<Elf64_Half, std::string_view> allVersionIds;
  std::unordered_map<Elf64_Half, std::string_view> versionIdsDefined;
  std::unordered_map<Elf64_Half, VersionNeededInfo> versionIdsNeeded;
};

struct SymbolTableView {
  SymbolTableView() = default;
  SymbolTableView(const SymbolTableView&) = delete;
  SymbolTableView(SymbolTableView&&) = default;
  SymbolTableView& operator=(const SymbolTableView&) = delete;
  SymbolTableView& operator=(SymbolTableView&&) = default;

  std::vector<std::tuple<std::string_view, SymbolInfo>> items; // keys are null-terminated
  SymbolVersionsCache version_info;
};

enum class SymbolKindFilter {
  Undefined = 1,
  Defined = 2,
};

constexpr SymbolKindFilter operator|(SymbolKindFilter lhs, SymbolKindFilter rhs) {
  return static_cast<SymbolKindFilter>(std::to_underlying(lhs) | std::to_underlying(rhs));
}

constexpr SymbolKindFilter operator&(SymbolKindFilter lhs, SymbolKindFilter rhs) {
  return static_cast<SymbolKindFilter>(std::to_underlying(lhs) & std::to_underlying(rhs));
}

class SymbolVersionFilter {
public:
  SymbolVersionFilter(std::vector<std::string> patterns) {
    any_filters_ = !patterns.empty();
    for (const auto& p : patterns) {
      if (p.starts_with("file:")) {
        auto value = p.substr(5);
        if (value == "+") {
          filter_any_file_ = true;
          filter_no_file_ = false;
        } else if (value == "-") {
          filter_any_file_ = false;
          filter_no_file_ = true;
        } else if (!value.empty()) {
          filter_files_.push_back(value + "\0"s); // to match the string views
        }
      } else if (p.starts_with("id:")) {
        auto value = p.substr(3);
        if (value == "hidden") {
          filter_hidden_ = true;
        } else {
          filter_ids_.push_back(static_cast<Elf64_Half>(std::stoi(value)));
        }
      }
    }
  }

  bool shouldInclude(const SymbolInfo& info, const SymbolVersionsCache& cache) const {
    if (!any_filters_) {
      return true;
    }
    auto hidden = (info.version_id & 1 << 15) != 0;
    auto id = info.version_id & 0x7FFF;
    if (hidden && filter_hidden_) {
      return true;
    }
    switch (id) {
    case 0:
    case 1:
      return filter_no_file_;
    default:
      if (filter_any_file_) {
        return true;
      }
      if (filter_files_.empty() && filter_ids_.empty()) {
        return false;
      }
      if (std::find(filter_ids_.begin(), filter_ids_.end(), id) != filter_ids_.end()) {
        return true;
      }
      if (auto it = cache.versionIdsNeeded.find(id); it != cache.versionIdsNeeded.end()) {
        if (std::find(filter_files_.begin(), filter_files_.end(), it->second.file) != filter_files_.end()) {
          return true;
        }
      }
    }
    return false;
  }

private:
  bool any_filters_{};
  bool filter_hidden_{};
  bool filter_any_file_{};
  bool filter_no_file_{};
  std::vector<std::string> filter_files_;
  std::vector<Elf64_Half> filter_ids_;
};

std::string_view strtabCStrView(bytes_view view) {
  auto strLen = std::distance(view.begin(), std::next(std::find(view.begin(), view.end(), 0u)));
  return to_string_view(view.first(strLen));
}

bool flag_demangle;

absl::StatusOr<SymbolTableView> readDynamicSymbols(const MmapFileHandle& f, SymbolKindFilter kind_filter) {
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

  bool showUndefined = (kind_filter & SymbolKindFilter::Undefined) == SymbolKindFilter::Undefined;
  bool showDefined = (kind_filter & SymbolKindFilter::Defined) == SymbolKindFilter::Defined;

  SymbolTableView out;

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
    case SHT_DYNAMIC:     sh_dynamic = sectionHeader; break;
    case SHT_DYNSYM:      sh_dynsym = sectionHeader; break;
    case SHT_GNU_versym:  sh_gnu_versym = sectionHeader; break;
    case SHT_GNU_verdef:  sh_gnu_verdef = sectionHeader; break;
    case SHT_GNU_verneed: sh_gnu_verneed = sectionHeader; break;
    default:
      continue;
    }
  }
  if (sh_dynamic == nullptr) {
    return absl::InvalidArgumentError("missing section: .dynamic");
  }
  if (sh_dynsym == nullptr) {
    return absl::InvalidArgumentError("missing section: .dynsym");
  }
  if (sh_gnu_versym == nullptr) {
    return absl::InvalidArgumentError("missing section: .gnu.version");
  }
  if (sh_gnu_verdef == nullptr) {
    return absl::InvalidArgumentError("missing section: .gnu.version_d");
  }
  if (sh_gnu_verneed == nullptr) {
    return absl::InvalidArgumentError("missing section: .gnu.version_r");
  }

  {
    Elf64_Xword numVerdefEntries{};
    Elf64_Xword numVerneedEntries{};
    auto dynamicEntries = extension_data.subspan(sh_dynamic->sh_offset, sh_dynamic->sh_size);
    while (!dynamicEntries.empty()) {
      auto* entry = reinterpret_cast<const Elf64_Dyn*>(dynamicEntries.data());
      switch (entry->d_tag) {
      case DT_VERDEFNUM:  numVerdefEntries = entry->d_un.d_val; break;
      case DT_VERNEEDNUM: numVerneedEntries = entry->d_un.d_val; break;
      default:            break;
      }
      dynamicEntries = dynamicEntries.subspan(sizeof(Elf64_Dyn));
    }

    {
      auto* verdefStrTabHdr = reinterpret_cast<const Elf64_Shdr*>(
        extension_data.subspan(header->e_shoff + sh_gnu_verdef->sh_link * sizeof(Elf64_Shdr), sizeof(Elf64_Shdr)).data());
      auto verdefStrTable = extension_data.subspan(verdefStrTabHdr->sh_offset, verdefStrTabHdr->sh_size);

      auto verdefEntries = extension_data.subspan(sh_gnu_verdef->sh_offset, sh_gnu_verdef->sh_size);
      for (size_t entryOffset = 0, n = 0;;) {
        assert(n < numVerdefEntries);
        auto* verdefEntry = reinterpret_cast<const Elf64_Verdef*>(
          verdefEntries.subspan(entryOffset, sizeof(Elf64_Verdef)).data());

        // skip the version for the file itself, only look at symbol versions
        if ((verdefEntry->vd_flags & VER_FLG_BASE) == 0) {
          if (verdefEntry->vd_cnt == 0) {
            std::cerr << "warn: section .gnu.version_d contains a version definition with no version name" << std::endl;
          } else if (verdefEntry->vd_cnt > 1) {
            std::cerr << "warn: section .gnu.version_d contains a version definition with multiple version names" << std::endl;
          } else {
            auto* aux = reinterpret_cast<const Elf64_Verdaux*>(
              verdefEntries.subspan(entryOffset + verdefEntry->vd_aux, sizeof(Elf64_Verdaux)).data());
            auto version_name = strtabCStrView(verdefStrTable.subspan(aux->vda_name));
            out.version_info.allVersionIds[verdefEntry->vd_ndx] = version_name;
            out.version_info.versionIdsDefined[verdefEntry->vd_ndx] = version_name;
          }
        }

        if (verdefEntry->vd_next == 0) {
          // this should always be hit if the file is well-formed
          break;
        }
        entryOffset += verdefEntry->vd_next;
        n++;
      }
    }

    {
      auto* verneedStrTabHdr = reinterpret_cast<const Elf64_Shdr*>(
        extension_data.subspan(header->e_shoff + sh_gnu_verneed->sh_link * sizeof(Elf64_Shdr), sizeof(Elf64_Shdr)).data());
      auto verneedStrTable = extension_data.subspan(verneedStrTabHdr->sh_offset, verneedStrTabHdr->sh_size);

      auto verneedEntries = extension_data.subspan(sh_gnu_verneed->sh_offset, sh_gnu_verneed->sh_size);
      for (size_t entryOffset = 0, n = 0;;) {
        assert(n < numVerneedEntries);
        auto* verneedEntry = reinterpret_cast<const Elf64_Verneed*>(
          verneedEntries.subspan(entryOffset, sizeof(Elf64_Verneed)).data());
        auto filename = strtabCStrView(verneedStrTable.subspan(verneedEntry->vn_file));

        if (verneedEntry->vn_cnt == 0) {
          std::cerr << "warn: section .gnu.version_r contains a version requirement with no version name" << std::endl;
        } else {
          for (size_t auxOffset = verneedEntry->vn_aux, a = 0;;) {
            assert(a < verneedEntry->vn_cnt);
            auto* auxEntry = reinterpret_cast<const Elf64_Vernaux*>(
              verneedEntries.subspan(entryOffset + auxOffset, sizeof(Elf64_Vernaux)).data());
            auto version_name = strtabCStrView(verneedStrTable.subspan(auxEntry->vna_name));
            out.version_info.allVersionIds[auxEntry->vna_other] = version_name;
            out.version_info.versionIdsNeeded[auxEntry->vna_other] = {
              .version = version_name,
              .file = filename,
            };
            if (auxEntry->vna_next == 0) {
              // this should always be hit if the file is well-formed
              break;
            }
            auxOffset += auxEntry->vna_next;
            a++;
          }
        }

        if (verneedEntry->vn_next == 0) {
          // this should always be hit if the file is well-formed
          break;
        }
        entryOffset += verneedEntry->vn_next;
        n++;
      }
    }
  }

  auto versymTable = extension_data.subspan(sh_gnu_versym->sh_offset, sh_gnu_versym->sh_size);

  auto* symbolStrTabHdr = reinterpret_cast<const Elf64_Shdr*>(
    extension_data.subspan(header->e_shoff + sh_dynsym->sh_link * sizeof(Elf64_Shdr), sizeof(Elf64_Shdr)).data());
  auto symbolStringTable = extension_data.subspan(symbolStrTabHdr->sh_offset, symbolStrTabHdr->sh_size);

  auto dynsymEntries = extension_data.subspan(sh_dynsym->sh_offset, sh_dynsym->sh_size);
  out.items.reserve(sh_dynsym->sh_size / sizeof(Elf64_Sym));
  assert(versymTable.size() == out.items.capacity() * sizeof(Elf64_Half));
  for (size_t i = 0; i < sh_dynsym->sh_size / sizeof(Elf64_Sym); i++) {
    auto* sym = reinterpret_cast<const Elf64_Sym*>(dynsymEntries.subspan(i * sizeof(Elf64_Sym), sizeof(Elf64_Sym)).data());
    if (sym->st_name != 0) {
      bool isUndefined = sym->st_shndx == SHN_UNDEF;
      if ((isUndefined && showUndefined) || (!isUndefined && showDefined)) {
        auto symName = strtabCStrView(symbolStringTable.subspan(sym->st_name));
        // find the corresponding entry in the versym table
        auto versionId = *reinterpret_cast<const Elf64_Half*>(
          versymTable.subspan(i * sizeof(Elf64_Half), sizeof(Elf64_Half)).data());
        out.items.emplace_back(symName, SymbolInfo{.index = i, .symbol = sym, .version_id = versionId});
      }
    }
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

enum class PrintVersions {
  None,
  All,
  Needed,
  Defined,
  Verbose,
};

absl::Status printDynamicSymbols(const MmapFileHandle& f,
                                 SymbolKindFilter filter,
                                 PrintVersions print_versions,
                                 const SymbolVersionFilter& version_filter) {
  auto dst = readDynamicSymbols(f, filter);
  if (!dst.ok()) {
    return dst.status();
  }
  char* buf{};
  size_t len = 0;
  const bool demangle = flag_demangle;
  for (const auto& [k, v] : dst->items) {
    if (!version_filter.shouldInclude(v, dst->version_info)) {
      continue;
    }

    if (demangle) {
      int status{};
      // note: the string views contain the null terminator
      buf = abi::__cxa_demangle(k.data(), buf, &len, &status); // NOLINT:bugprone-suspicious-stringview-data-usage
      switch (status) {
      case 0:
        std::cout << buf;
        break;
      case -2:
        std::cout << k.substr(0, k.size() - 1);
        break;
      default:
        free(buf);
        return absl::InternalError(fmt::format("__cxa_demangle error {}", status));
      }
    } else {
      std::cout << k.substr(0, k.size() - 1);
    }

    bool hidden = (v.version_id & 1 << 15) != 0;
    auto vid = v.version_id & 0x7FFF;

    if (v.version_id < 2) {
      goto no_version;
    }
    switch (print_versions) {
    case PrintVersions::None:
    no_version:
      std::cout << "\n";
      break;
    case PrintVersions::All:
      std::cout << "@" << dst->version_info.allVersionIds[vid] << "\n";
      break;
    case PrintVersions::Needed:
      if (auto it = dst->version_info.versionIdsNeeded.find(vid);
          it != dst->version_info.versionIdsNeeded.end()) {
        std::cout << "@" << it->second.version << "\n";
      }
      break;
    case PrintVersions::Defined:
      if (auto it = dst->version_info.versionIdsDefined.find(vid);
          it != dst->version_info.versionIdsDefined.end()) {
        std::cout << "@" << it->second << "\n";
      }
      break;
    case PrintVersions::Verbose:
      if (auto it = dst->version_info.versionIdsNeeded.find(vid);
          it != dst->version_info.versionIdsNeeded.end()) {
        std::cout << fmt::format("@{} [needed; id:{}; file:{}{}]\n", it->second.version, vid, it->second.file,
                                 hidden ? "; hidden" : "");
      } else if (auto it = dst->version_info.versionIdsDefined.find(vid);
                 it != dst->version_info.versionIdsDefined.end()) {
        std::cout << fmt::format("@{} [defined; id:{}{}]\n", it->second, vid,
                                 hidden ? "; hidden" : "");
      }
    }
  }
  free(buf);
  std::cout.flush();

  return absl::OkStatus();
}

absl::Status checkCompatibility(const MmapFileHandle& host, const MmapFileHandle& ext) {
  auto extUndefined = readDynamicSymbols(ext, SymbolKindFilter::Undefined);
  if (!extUndefined.ok()) {
    return extUndefined.status();
  }

  auto hostDefined = readDynamicSymbols(host, SymbolKindFilter::Defined);
  if (!hostDefined.ok()) {
    return hostDefined.status();
  }

  return absl::OkStatus();
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
    .nargs(0, 1)
    .choices("undefined"s, "defined"s, "all"s);

  modes.add_argument("-c", "--check")
    .help("Check if the extension is compatible with the given binary")
    .nargs(1)
    .flag();

  cmd.add_argument("-d", "--demangle")
    .help("Demangle C++ symbols")
    .flag()
    .store_into(flag_demangle);

  cmd.add_argument("-v", "--versions")
    .help("Show symbol versions")
    .default_value("all")
    .nargs(1)
    .choices("none", "all", "needed", "defined", "verbose");

  cmd.add_argument("-f", "--filter")
    .help("When printing symbols, only include those matching the given patterns.\n"
          "Can be repeated; specify one pattern per --filter flag. Patterns are OR'd together.")
    .append()
    .nargs(1);

  cmd.add_argument("filename")
    .nargs(1)
    .required()
    .help("Path to an extension binary");

  cmd.add_epilog(R"(
'--symbols' options:
  undefined    | print undefined symbols (default)
  defined      | print defined symbols
  all          | print both defined and undefined symbols

'--versions' options:
  none         | do not print any symbol versions
  all          | always print symbol versions (default)
  needed       | only print versions for symbols needed from a dependency
  defined      | only print versions for symbols defined in the file
  verbose      | always print symbol versions; also show dependency filenames

'--filter' pattern syntax:
  file:<name>  | filter needed symbols by dependency filename; also accepts "+" for any filename
                 or "-" for no filename (ex: "file:libc.so.6", "file:+", "file:-")
  id:<number>  | filter symbols by version id; also accepts "hidden" for any id with bit 15 set
                 (ex: "id:0", "id:2", "id:hidden"))"s.substr(1));

  cmd.set_usage_break_on_mutex();

  try {
    cmd.parse_args(argc, argv);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return 1;
  }

  static const std::unordered_map<std::string_view, SymbolKindFilter> filterModeLookup{
    {"undefined"sv, SymbolKindFilter::Undefined},
    {"defined"sv, SymbolKindFilter::Defined},
    {"all"sv, SymbolKindFilter::Undefined | SymbolKindFilter::Defined},
  };

  static const std::unordered_map<std::string_view, PrintVersions> printVersionsLookup{
    {"none"sv, PrintVersions::None},
    {"all"sv, PrintVersions::All},
    {"needed"sv, PrintVersions::Needed},
    {"defined"sv, PrintVersions::Defined},
    {"verbose"sv, PrintVersions::Verbose},
  };

  auto filename = cmd.get("filename");
  auto stat = [&] {
    auto f = mmapFile(filename);
    if (!f.ok()) {
      return f.status();
    }
    if (cmd.is_used("--metadata")) {
      return printMetadata(**f);
    } else if (cmd.is_used("--symbols")) {
      SymbolVersionFilter versionFilter(cmd.get<std::vector<std::string>>("--filter"));
      return printDynamicSymbols(**f,
                                 filterModeLookup.at(cmd.get("--symbols")),
                                 printVersionsLookup.at(cmd.get("--versions")),
                                 versionFilter);
    } else if (cmd.is_used("--check")) {
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