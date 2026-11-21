// Path normalisation so that evidence never carries a user name or machine-specific
// prefix (roadmap section 7, point 2).
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace aegis {

class PathNormaliser {
 public:
  // `prefixes` maps real directories to tokens, for example
  // {L"C:\\Users\\jack\\AppData\\Local", L"%LOCALAPPDATA%"}. Longest prefixes win.
  void AddPrefix(std::wstring dir, std::wstring token);

  // Returns the path with known prefixes replaced by tokens, a leading "\\?\" removed,
  // and any remaining "<drive>:\Users\<name>" replaced by "%USERPROFILE%" so another
  // account's name does not leak either.
  std::wstring Normalise(const std::wstring& path) const;

  // Reverse of Normalise for a path that starts with one of the tokens.
  std::wstring Expand(const std::wstring& tokenised) const;

 private:
  std::vector<std::pair<std::wstring, std::wstring>> prefixes_;  // sorted longest first
};

// True if a *normalised* path is in a location an unprivileged user can write to.
bool IsUserWritable(const std::wstring& normalised);

// True if a normalised path is inside a Roblox (or Bloxstrap/Fishstrap) version folder,
// where Roblox's own DLLs live.
bool IsRobloxInstallPath(const std::wstring& normalised);

}  // namespace aegis
