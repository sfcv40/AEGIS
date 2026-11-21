#include "privacy.h"

#include <algorithm>
#include <cwctype>

#include "strutil.h"

namespace aegis {

void PathNormaliser::AddPrefix(std::wstring dir, std::wstring token) {
  while (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/')) dir.pop_back();
  if (dir.empty()) return;
  prefixes_.emplace_back(std::move(dir), std::move(token));
  std::stable_sort(prefixes_.begin(), prefixes_.end(),
                   [](const auto& a, const auto& b) { return a.first.size() > b.first.size(); });
}

static bool PrefixAtBoundary(const std::wstring& path, const std::wstring& dir) {
  if (!IStartsWith(path, dir)) return false;
  return path.size() == dir.size() || path[dir.size()] == L'\\' || path[dir.size()] == L'/';
}

std::wstring PathNormaliser::Normalise(const std::wstring& in) const {
  std::wstring path = in;
  if (path.rfind(L"\\\\?\\", 0) == 0 || path.rfind(L"\\??\\", 0) == 0) path = path.substr(4);
  for (const auto& [dir, token] : prefixes_) {
    if (PrefixAtBoundary(path, dir)) return token + path.substr(dir.size());
  }
  // Generic "<X>:\Users\<name>" catch-all for other profiles.
  if (path.size() > 9 && std::iswalpha(path[0]) && path[1] == L':' && IStartsWith(path.substr(2), L"\\Users\\")) {
    size_t name_start = 9;
    size_t name_end = path.find(L'\\', name_start);
    std::wstring name = path.substr(name_start, name_end == std::wstring::npos ? std::wstring::npos : name_end - name_start);
    if (!IEquals(name, L"Public") && !IEquals(name, L"Default") && !IEquals(name, L"All Users") &&
        !IEquals(name, L"Default User")) {
      return L"%USERPROFILE%" + (name_end == std::wstring::npos ? std::wstring() : path.substr(name_end));
    }
    if (IEquals(name, L"Public")) {
      return L"%PUBLIC%" + (name_end == std::wstring::npos ? std::wstring() : path.substr(name_end));
    }
  }
  return path;
}

std::wstring PathNormaliser::Expand(const std::wstring& tokenised) const {
  for (const auto& [dir, token] : prefixes_) {
    if (IStartsWith(tokenised, token)) return dir + tokenised.substr(token.size());
  }
  return tokenised;
}

bool IsUserWritable(const std::wstring& p) {
  static const wchar_t* kRoots[] = {L"%USERPROFILE%\\", L"%LOCALAPPDATA%\\", L"%APPDATA%\\", L"%TEMP%\\",
                                    L"%PUBLIC%\\",      L"%SystemRoot%\\Temp\\"};
  for (auto r : kRoots)
    if (IStartsWith(p, r)) return true;
  return false;
}

bool IsRobloxInstallPath(const std::wstring& p) {
  static const wchar_t* kRoots[] = {L"%LOCALAPPDATA%\\Roblox\\Versions\\", L"%LOCALAPPDATA%\\Bloxstrap\\Versions\\",
                                    L"%LOCALAPPDATA%\\Fishstrap\\Versions\\", L"%ProgramFiles(x86)%\\Roblox\\Versions\\",
                                    L"%ProgramFiles%\\Roblox\\Versions\\"};
  for (auto r : kRoots)
    if (IStartsWith(p, r)) return true;
  return false;
}

}  // namespace aegis
