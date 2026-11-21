// Findings and the reporter.
//
// Privacy (roadmap section 7): AEGIS only ever emits rule hits. Every value placed in
// a Finding's evidence must already be safe to leave the machine: rule ids, hashes,
// signer names, access masks, timestamps and *normalised* paths (see privacy.h).
// Never put raw command lines, script text, window titles of other apps or user names
// into evidence.
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <ostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "rulemeta.h"

namespace aegis {

struct Finding {
  std::string rule;  // rule id, must exist in the catalog unless title/severity are set
  std::vector<std::pair<std::string, std::string>> evidence;
  uint32_t pid = 0;      // process the finding is about, for correlation (0 = none)
  std::string dedupe;    // extra dedupe key; the reporter always includes rule + pid

  // Optional overrides, used for YARA hits whose metadata comes from the .yar file.
  std::string title, severity, confidence, family;

  Finding& Add(std::string k, std::string v) {
    evidence.emplace_back(std::move(k), std::move(v));
    return *this;
  }
};

std::string JsonEscape(const std::string& s);

class Reporter {
 public:
  Reporter(const RuleCatalog& catalog, std::ostream& out) : catalog_(catalog), out_(out) {}

  // Emits the finding as one JSON line unless an identical one (rule + pid + dedupe)
  // was already reported. Returns true if it was emitted. Thread-safe.
  bool Report(Finding f);

  // Writes the closing summary line: counts per rule, no evidence.
  void Summary(const std::string& mode, const std::vector<std::string>& checks_run,
               const std::vector<std::string>& checks_skipped);

  size_t HitCount() const;
  // True if `rule` already fired for `pid` this session.
  bool Fired(const std::string& rule, uint32_t pid) const;

 private:
  const RuleCatalog& catalog_;
  std::ostream& out_;
  mutable std::mutex mu_;
  std::set<std::string> seen_;
  std::map<uint32_t, std::set<std::string>> by_pid_;
  std::map<std::string, size_t> counts_;
};

}  // namespace aegis
