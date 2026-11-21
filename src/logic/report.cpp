#include "report.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>

namespace aegis {

std::string JsonEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

namespace {

std::string NowIso() {
  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#ifdef _WIN32
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

std::string JsonList(const std::vector<std::string>& v) {
  std::string s = "[";
  for (size_t i = 0; i < v.size(); ++i) {
    if (i) s += ",";
    s += "\"" + JsonEscape(v[i]) + "\"";
  }
  return s + "]";
}

bool Contains(const std::vector<std::string>& v, const std::string& x) {
  return std::find(v.begin(), v.end(), x) != v.end();
}

}  // namespace

bool Reporter::Report(Finding f) {
  std::lock_guard<std::mutex> lock(mu_);
  std::string key = f.rule + "|" + std::to_string(f.pid) + "|" + f.dedupe;
  if (!seen_.insert(key).second) return false;

  const RuleMeta* meta = catalog_.Find(f.rule);
  std::string title = !f.title.empty() ? f.title : meta ? meta->title : f.rule;
  std::string severity = !f.severity.empty() ? f.severity : meta ? meta->severity : "medium";
  std::string confidence = !f.confidence.empty() ? f.confidence : meta ? meta->confidence : "medium";

  // Correlation: a rule listed in `correlate` (either direction) that already fired
  // for the same process raises confidence to high.
  std::vector<std::string> correlated;
  if (f.pid != 0) {
    auto it = by_pid_.find(f.pid);
    if (it != by_pid_.end()) {
      for (const auto& other : it->second) {
        if (other == f.rule) continue;
        const RuleMeta* om = catalog_.Find(other);
        bool linked = (meta && Contains(meta->correlate, other)) || (om && Contains(om->correlate, f.rule));
        if (linked) correlated.push_back(other);
      }
    }
    by_pid_[f.pid].insert(f.rule);
  }
  if (!correlated.empty()) confidence = "high";
  counts_[f.rule]++;

  std::string line = "{\"type\":\"finding\",\"time\":\"" + NowIso() + "\",\"rule\":\"" + JsonEscape(f.rule) +
                     "\",\"title\":\"" + JsonEscape(title) + "\",\"severity\":\"" + JsonEscape(severity) +
                     "\",\"confidence\":\"" + JsonEscape(confidence) + "\"";
  if (meta && !meta->roadmap.empty()) line += ",\"roadmap\":" + JsonList(meta->roadmap);
  if (!f.family.empty()) line += ",\"families\":" + JsonList({f.family});
  else if (meta && !meta->families.empty()) line += ",\"families\":" + JsonList(meta->families);
  if (f.pid) line += ",\"pid\":" + std::to_string(f.pid);
  line += ",\"evidence\":{";
  for (size_t i = 0; i < f.evidence.size(); ++i) {
    if (i) line += ",";
    line += "\"" + JsonEscape(f.evidence[i].first) + "\":\"" + JsonEscape(f.evidence[i].second) + "\"";
  }
  line += "}";
  if (!correlated.empty()) line += ",\"correlated_with\":" + JsonList(correlated);
  line += "}\n";
  out_ << line;
  out_.flush();
  return true;
}

void Reporter::Summary(const std::string& mode, const std::vector<std::string>& checks_run,
                       const std::vector<std::string>& checks_skipped) {
  std::lock_guard<std::mutex> lock(mu_);
  std::string line = "{\"type\":\"summary\",\"time\":\"" + NowIso() + "\",\"mode\":\"" + JsonEscape(mode) +
                     "\",\"checks_run\":" + JsonList(checks_run) + ",\"checks_skipped\":" + JsonList(checks_skipped) +
                     ",\"hits\":{";
  bool first = true;
  for (const auto& [rule, n] : counts_) {
    if (!first) line += ",";
    first = false;
    line += "\"" + JsonEscape(rule) + "\":" + std::to_string(n);
  }
  line += "}}\n";
  out_ << line;
  out_.flush();
}

size_t Reporter::HitCount() const {
  std::lock_guard<std::mutex> lock(mu_);
  size_t n = 0;
  for (const auto& [_, c] : counts_) n += c;
  return n;
}

bool Reporter::Fired(const std::string& rule, uint32_t pid) const {
  std::lock_guard<std::mutex> lock(mu_);
  auto it = by_pid_.find(pid);
  return it != by_pid_.end() && it->second.count(rule) > 0;
}

}  // namespace aegis
