#include "yara_engine.h"

#include <mutex>

#ifdef AEGIS_WITH_YARA
#include <yara.h>
#endif

namespace aegis {

#ifdef AEGIS_WITH_YARA

namespace {
std::once_flag g_init;

int OnMatch(YR_SCAN_CONTEXT*, int message, void* message_data, void* user_data) {
  if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
  auto* rule = static_cast<YR_RULE*>(message_data);
  auto* out = static_cast<std::vector<YaraMatch>*>(user_data);
  YaraMatch m;
  m.rule = rule->identifier;
  YR_META* meta;
  yr_rule_metas_foreach(rule, meta) {
    if (meta->type != META_TYPE_STRING) continue;
    std::string key = meta->identifier;
    if (key == "family") m.family = meta->string;
    else if (key == "severity") m.severity = meta->string;
    else if (key == "description") m.description = meta->string;
  }
  out->push_back(std::move(m));
  return CALLBACK_CONTINUE;
}

void OnCompileError(int level, const char* file, int line, const YR_RULE*, const char* msg, void* user) {
  if (level != YARA_ERROR_LEVEL_ERROR) return;
  auto* err = static_cast<std::string*>(user);
  *err += std::string(file ? file : "<rules>") + ":" + std::to_string(line) + ": " + msg + "\n";
}
}  // namespace

YaraEngine::YaraEngine() { std::call_once(g_init, [] { yr_initialize(); }); }

YaraEngine::~YaraEngine() {
  if (rules_) yr_rules_destroy(static_cast<YR_RULES*>(rules_));
}

bool YaraEngine::Available() { return true; }

bool YaraEngine::Compile(const std::vector<std::pair<std::string, std::string>>& sources, std::string& error) {
  YR_COMPILER* c = nullptr;
  if (yr_compiler_create(&c) != ERROR_SUCCESS) {
    error = "yr_compiler_create failed";
    return false;
  }
  yr_compiler_set_callback(c, OnCompileError, &error);
  int errors = 0;
  for (const auto& [ns, text] : sources) errors += yr_compiler_add_string(c, text.c_str(), ns.c_str());
  YR_RULES* rules = nullptr;
  if (errors == 0 && yr_compiler_get_rules(c, &rules) == ERROR_SUCCESS) rules_ = rules;
  yr_compiler_destroy(c);
  return rules_ != nullptr;
}

std::vector<YaraMatch> YaraEngine::ScanFile(const std::wstring& path) const {
  std::vector<YaraMatch> out;
  if (!rules_) return out;
  // Scan through a HANDLE so non-ASCII paths work.
  HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                         OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  if (f == INVALID_HANDLE_VALUE) return out;
  yr_rules_scan_fd(static_cast<YR_RULES*>(rules_), f, SCAN_FLAGS_FAST_MODE, OnMatch, &out, 30);
  CloseHandle(f);
  return out;
}

std::vector<YaraMatch> YaraEngine::ScanMemory(const void* data, size_t len) const {
  std::vector<YaraMatch> out;
  if (!rules_ || !len) return out;
  yr_rules_scan_mem(static_cast<YR_RULES*>(rules_), static_cast<const uint8_t*>(data), len, SCAN_FLAGS_FAST_MODE,
                    OnMatch, &out, 30);
  return out;
}

#else  // !AEGIS_WITH_YARA

YaraEngine::YaraEngine() = default;
YaraEngine::~YaraEngine() = default;
bool YaraEngine::Available() { return false; }
bool YaraEngine::Compile(const std::vector<std::pair<std::string, std::string>>&, std::string& error) {
  error = "built without YARA (AEGIS_WITH_YARA=OFF)";
  return false;
}
std::vector<YaraMatch> YaraEngine::ScanFile(const std::wstring&) const { return {}; }
std::vector<YaraMatch> YaraEngine::ScanMemory(const void*, size_t) const { return {}; }

#endif

}  // namespace aegis
