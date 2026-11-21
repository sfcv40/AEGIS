#include "strutil.h"

#include <cstdio>
#include <cwctype>

namespace aegis {

std::wstring ToLower(std::wstring_view s) {
  std::wstring out(s);
  for (auto& c : out) c = static_cast<wchar_t>(std::towlower(c));
  return out;
}

bool IEquals(std::wstring_view a, std::wstring_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i)
    if (std::towlower(a[i]) != std::towlower(b[i])) return false;
  return true;
}

bool IStartsWith(std::wstring_view s, std::wstring_view prefix) {
  return s.size() >= prefix.size() && IEquals(s.substr(0, prefix.size()), prefix);
}

bool IEndsWith(std::wstring_view s, std::wstring_view suffix) {
  return s.size() >= suffix.size() && IEquals(s.substr(s.size() - suffix.size()), suffix);
}

bool IContains(std::wstring_view haystack, std::wstring_view needle) {
  if (needle.empty()) return true;
  return ToLower(haystack).find(ToLower(needle)) != std::wstring::npos;
}

std::wstring BaseName(std::wstring_view path) {
  auto pos = path.find_last_of(L"\\/");
  return std::wstring(pos == std::wstring_view::npos ? path : path.substr(pos + 1));
}

std::wstring DirName(std::wstring_view path) {
  auto pos = path.find_last_of(L"\\/");
  return pos == std::wstring_view::npos ? std::wstring() : std::wstring(path.substr(0, pos));
}

static void AppendUtf8(std::string& out, uint32_t cp) {
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xC0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xE0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else {
    out += static_cast<char>(0xF0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
}

std::string WideToUtf8(std::wstring_view s) {
  std::string out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    uint32_t c = static_cast<uint32_t>(s[i]);
    if constexpr (sizeof(wchar_t) == 2) {
      if (c >= 0xD800 && c <= 0xDBFF && i + 1 < s.size()) {
        uint32_t lo = static_cast<uint32_t>(s[i + 1]);
        if (lo >= 0xDC00 && lo <= 0xDFFF) {
          c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
          ++i;
        }
      }
    }
    if (c >= 0xD800 && c <= 0xDFFF) c = 0xFFFD;  // lone surrogate
    AppendUtf8(out, c);
  }
  return out;
}

std::wstring Utf8ToWide(std::string_view s) {
  std::wstring out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size();) {
    unsigned char b = static_cast<unsigned char>(s[i]);
    uint32_t cp;
    size_t n;
    if (b < 0x80) { cp = b; n = 1; }
    else if ((b >> 5) == 0x6) { cp = b & 0x1F; n = 2; }
    else if ((b >> 4) == 0xE) { cp = b & 0x0F; n = 3; }
    else if ((b >> 3) == 0x1E) { cp = b & 0x07; n = 4; }
    else { out += L'\xFFFD'; ++i; continue; }
    if (i + n > s.size()) { out += L'\xFFFD'; break; }
    for (size_t k = 1; k < n; ++k) cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3F);
    i += n;
    if constexpr (sizeof(wchar_t) == 2) {
      if (cp >= 0x10000) {
        cp -= 0x10000;
        out += static_cast<wchar_t>(0xD800 + (cp >> 10));
        out += static_cast<wchar_t>(0xDC00 + (cp & 0x3FF));
        continue;
      }
    }
    out += static_cast<wchar_t>(cp);
  }
  return out;
}

std::string Hex32(uint32_t v) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "0x%08X", v);
  return buf;
}

template <typename S, typename V>
static S TrimImpl(V s) {
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
  return S(s.substr(b, e - b));
}

std::wstring Trim(std::wstring_view s) { return TrimImpl<std::wstring>(s); }
std::string Trim(std::string_view s) { return TrimImpl<std::string>(s); }

template <typename S, typename V>
static std::vector<S> SplitLinesImpl(V s) {
  std::vector<S> out;
  size_t start = 0;
  for (size_t i = 0; i <= s.size(); ++i) {
    if (i == s.size() || s[i] == '\n') {
      V line = s.substr(start, i - start);
      if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
      if (i < s.size() || !line.empty()) out.emplace_back(line);
      start = i + 1;
    }
  }
  return out;
}

std::vector<std::wstring> SplitLines(std::wstring_view s) { return SplitLinesImpl<std::wstring>(s); }
std::vector<std::string> SplitLines(std::string_view s) { return SplitLinesImpl<std::string>(s); }

}  // namespace aegis
