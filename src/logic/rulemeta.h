// Rule metadata (id, title, severity, confidence, roadmap, correlate) read from the
// behaviour YAML and Sigma files in rules/. Those files stay the single source of
// truth: the binary embeds them at build time and the detectors refer to rules by id.
//
// Only the flat metadata keys are parsed. The `match:` blocks document what each
// detector implements; the matching itself is code in src/win/ and src/logic/.
#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace aegis {

struct RuleMeta {
  std::string id;
  std::string title;
  std::string severity = "medium";    // low | medium | high | critical
  std::string confidence = "medium";  // low | medium | high
  std::vector<std::string> roadmap;
  std::vector<std::string> families;
  std::vector<std::string> correlate;
};

// Parses a behaviour rule file: a YAML list whose items start with "- id:".
std::vector<RuleMeta> ParseBehaviorYaml(std::string_view text);

// Parses one Sigma rule. The rule id becomes "SIGMA-<sigma id>".
// level maps to severity; confidence is "medium".
RuleMeta ParseSigmaYaml(std::string_view text);

class RuleCatalog {
 public:
  void Add(const RuleMeta& m) { rules_[m.id] = m; }
  const RuleMeta* Find(const std::string& id) const;
  const std::map<std::string, RuleMeta>& All() const { return rules_; }

 private:
  std::map<std::string, RuleMeta> rules_;
};

}  // namespace aegis
