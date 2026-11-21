// Portable string helpers. No Windows headers here, so the logic layer builds and
// is unit-tested on any platform.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace aegis {

std::wstring ToLower(std::wstring_view s);
bool IEquals(std::wstring_view a, std::wstring_view b);
bool IStartsWith(std::wstring_view s, std::wstring_view prefix);
bool IEndsWith(std::wstring_view s, std::wstring_view suffix);
bool IContains(std::wstring_view haystack, std::wstring_view needle);

// Final path component, split on '\' or '/'.
std::wstring BaseName(std::wstring_view path);
// Everything before the final component, without the trailing separator.
std::wstring DirName(std::wstring_view path);

std::string WideToUtf8(std::wstring_view s);
std::wstring Utf8ToWide(std::string_view s);

std::string Hex32(uint32_t v);  // "0x00000438"
std::wstring Trim(std::wstring_view s);
std::string Trim(std::string_view s);
std::vector<std::wstring> SplitLines(std::wstring_view s);
std::vector<std::string> SplitLines(std::string_view s);

}  // namespace aegis
