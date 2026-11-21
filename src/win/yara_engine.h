// Thin wrapper over libyara. Built as a stub when AEGIS_WITH_YARA is off.
#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace aegis {

struct YaraMatch {
  std::string rule;
  std::string family;
  std::string severity;
  std::string description;
};

class YaraEngine {
 public:
  YaraEngine();
  ~YaraEngine();
  // sources: (namespace, rule text)
  bool Compile(const std::vector<std::pair<std::string, std::string>>& sources, std::string& error);
  bool Ready() const { return rules_ != nullptr; }
  std::vector<YaraMatch> ScanFile(const std::wstring& path) const;
  std::vector<YaraMatch> ScanMemory(const void* data, size_t len) const;
  static bool Available();

 private:
  void* rules_ = nullptr;
};

}  // namespace aegis
