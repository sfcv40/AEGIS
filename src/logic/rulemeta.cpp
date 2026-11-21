#include "rulemeta.h"

#include "strutil.h"

namespace aegis {

namespace {

std::string Unquote(std::string v) {
  v = Trim(v);
  // Drop a trailing comment that is not inside quotes.
  if (!v.empty() && v[0] != '\'' && v[0] != '"') {
    auto hash = v.find(" #");
    if (hash != std::string::npos) v = Trim(std::string_view(v).substr(0, hash));
  }
  if (v.size() >= 2 && ((v.front() == '\'' && v.back() == '\'') || (v.front() == '"' && v.back() == '"')))
    v = v.substr(1, v.size() - 2);
  return v;
}

std::vector<std::string> ParseFlowList(const std::string& raw) {
  std::vector<std::string> out;
  std::string v = Trim(raw);
  if (v.size() < 2 || v.front() != '[') return out;
  auto close = v.find(']');
  if (close == std::string::npos) return out;
  std::string body = v.substr(1, close - 1);
  size_t start = 0;
  for (size_t i = 0; i <= body.size(); ++i) {
    if (i == body.size() || body[i] == ',') {
      std::string item = Unquote(body.substr(start, i - start));
      if (!item.empty()) out.push_back(item);
      start = i + 1;
    }
  }
  return out;
}

// Splits "key: value" for a line whose indentation equals `indent`.
bool KeyValue(const std::string& line, size_t indent, std::string& key, std::string& value) {
  if (line.size() <= indent) return false;
  for (size_t i = 0; i < indent; ++i)
    if (line[i] != ' ') return false;
  if (line[indent] == ' ' || line[indent] == '#') return false;
  auto colon = line.find(':', indent);
  if (colon == std::string::npos) return false;
  key = Trim(std::string_view(line).substr(indent, colon - indent));
  value = line.substr(colon + 1);
  return true;
}

}  // namespace

std::vector<RuleMeta> ParseBehaviorYaml(std::string_view text) {
  std::vector<RuleMeta> out;
  RuleMeta* cur = nullptr;
  for (const auto& line : SplitLines(text)) {
    if (line.rfind("- id:", 0) == 0) {
      out.emplace_back();
      cur = &out.back();
      cur->id = Unquote(line.substr(5));
      continue;
    }
    if (!cur) continue;
    std::string key, value;
    if (!KeyValue(line, 2, key, value)) continue;
    if (key == "title") cur->title = Unquote(value);
    else if (key == "severity") cur->severity = Unquote(value);
    else if (key == "confidence") cur->confidence = Unquote(value);
    else if (key == "roadmap") cur->roadmap = ParseFlowList(value);
    else if (key == "families") cur->families = ParseFlowList(value);
    else if (key == "correlate") cur->correlate = ParseFlowList(value);
  }
  return out;
}

RuleMeta ParseSigmaYaml(std::string_view text) {
  RuleMeta m;
  m.confidence = "medium";
  for (const auto& line : SplitLines(text)) {
    std::string key, value;
    if (!KeyValue(line, 0, key, value)) continue;
    if (key == "title") m.title = Unquote(value);
    else if (key == "id") m.id = "SIGMA-" + Unquote(value);
    else if (key == "level") {
      std::string lvl = Unquote(value);
      m.severity = (lvl == "informational") ? "low" : lvl;
    }
  }
  m.roadmap = {"B6"};
  return m;
}

const RuleMeta* RuleCatalog::Find(const std::string& id) const {
  auto it = rules_.find(id);
  return it == rules_.end() ? nullptr : &it->second;
}

}  // namespace aegis
