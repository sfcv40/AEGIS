#include "winutil.h"

// clang-format off
#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
// clang-format on

#include <cstdarg>
#include <cstdio>
#include <ctime>

#include "../logic/strutil.h"
#include "nt.h"

namespace aegis::nt {
const Api& Get() {
  static Api api = [] {
    Api a;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
      a.QuerySystemInformation =
          reinterpret_cast<NtQuerySystemInformationFn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
      a.QueryInformationProcess =
          reinterpret_cast<NtQueryInformationProcessFn>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
      a.OpenDirectoryObject =
          reinterpret_cast<NtOpenDirectoryObjectFn>(GetProcAddress(ntdll, "NtOpenDirectoryObject"));
      a.QueryDirectoryObject =
          reinterpret_cast<NtQueryDirectoryObjectFn>(GetProcAddress(ntdll, "NtQueryDirectoryObject"));
    }
    return a;
  }();
  return api;
}
}  // namespace aegis::nt

namespace aegis::win {

namespace {
struct HandleCloser {
  HANDLE h;
  ~HandleCloser() {
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
  }
};
}  // namespace

void Log(const char* fmt, ...) {
  static std::mutex mu;
  std::lock_guard<std::mutex> lock(mu);
  va_list ap;
  va_start(ap, fmt);
  std::fputs("[aegis] ", stderr);
  std::vfprintf(stderr, fmt, ap);
  std::fputc('\n', stderr);
  va_end(ap);
}

bool IsElevated() {
  HANDLE tok = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
  HandleCloser c{tok};
  TOKEN_ELEVATION e{};
  DWORD len = 0;
  return GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &len) && e.TokenIsElevated;
}

bool EnablePrivilege(const wchar_t* name) {
  HANDLE tok = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
  HandleCloser c{tok};
  TOKEN_PRIVILEGES tp{};
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (!LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)) return false;
  if (!AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr)) return false;
  return GetLastError() == ERROR_SUCCESS;
}

std::vector<std::string> HardenSelf() {
  std::vector<std::string> failed;
  // Only load images signed by Microsoft: AEGIS links its CRT and libyara statically,
  // so the only DLLs it needs are Windows system DLLs. This blocks DLL planting and
  // most injected cheat helpers.
  PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
  sig.MicrosoftSignedOnly = 1;
  if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &sig, sizeof(sig))) failed.push_back("signature_policy");

  PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ext{};
  ext.DisableExtensionPoints = 1;
  if (!SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &ext, sizeof(ext)))
    failed.push_back("extension_points");

  PROCESS_MITIGATION_IMAGE_LOAD_POLICY img{};
  img.NoRemoteImages = 1;
  img.NoLowMandatoryLabelImages = 1;
  img.PreferSystem32Images = 1;
  if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &img, sizeof(img))) failed.push_back("image_load");

  PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn{};
  dyn.ProhibitDynamicCode = 1;
  if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dyn, sizeof(dyn))) failed.push_back("dynamic_code");
  return failed;
}

std::wstring GetEnv(const wchar_t* name) {
  wchar_t buf[32768];
  DWORD n = GetEnvironmentVariableW(name, buf, static_cast<DWORD>(std::size(buf)));
  return (n && n < std::size(buf)) ? std::wstring(buf, n) : std::wstring();
}

std::wstring ExpandEnv(const std::wstring& s) {
  wchar_t buf[32768];
  DWORD n = ExpandEnvironmentStringsW(s.c_str(), buf, static_cast<DWORD>(std::size(buf)));
  return (n && n <= std::size(buf)) ? std::wstring(buf) : s;
}

std::wstring KnownFolder(const GUID& id) {
  PWSTR p = nullptr;
  std::wstring out;
  if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p)) && p) out = p;
  if (p) CoTaskMemFree(p);
  return out;
}

std::wstring WindowsDir() {
  wchar_t buf[MAX_PATH];
  UINT n = GetSystemWindowsDirectoryW(buf, MAX_PATH);
  return (n && n < MAX_PATH) ? std::wstring(buf, n) : L"C:\\Windows";
}

static std::vector<std::pair<std::wstring, std::wstring>> DeviceMap() {
  std::vector<std::pair<std::wstring, std::wstring>> map;
  wchar_t drives[512];
  DWORD n = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives)), drives);
  for (wchar_t* d = drives; n && *d; d += wcslen(d) + 1) {
    std::wstring letter(d, 2);  // "C:"
    wchar_t target[1024];
    if (QueryDosDeviceW(letter.c_str(), target, static_cast<DWORD>(std::size(target))))
      map.emplace_back(target, letter);
  }
  return map;
}

std::wstring ToWin32Path(const std::wstring& native) {
  static std::mutex mu;
  static std::vector<std::pair<std::wstring, std::wstring>> map;
  static ULONGLONG built = 0;
  std::wstring p = native;
  if (p.rfind(L"\\??\\", 0) == 0) p = p.substr(4);
  if (p.rfind(L"\\\\?\\", 0) == 0) p = p.substr(4);
  if (IStartsWith(p, L"\\SystemRoot\\")) return WindowsDir() + p.substr(11);
  if (IStartsWith(p, L"System32\\") || IStartsWith(p, L"SysWOW64\\")) return WindowsDir() + L"\\" + p;
  if (IStartsWith(p, L"%SystemRoot%")) return WindowsDir() + p.substr(12);
  if (IStartsWith(p, L"\\Device\\")) {
    std::lock_guard<std::mutex> lock(mu);
    if (map.empty() || GetTickCount64() - built > 60000) {
      map = DeviceMap();
      built = GetTickCount64();
    }
    for (const auto& [dev, letter] : map) {
      if (IStartsWith(p, dev) && (p.size() == dev.size() || p[dev.size()] == L'\\'))
        return letter + p.substr(dev.size());
    }
  }
  return p;
}

bool FileExists(const std::wstring& path) {
  DWORD a = GetFileAttributesW(path.c_str());
  return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::optional<FILETIME> LastWriteTime(const std::wstring& path) {
  WIN32_FILE_ATTRIBUTE_DATA d{};
  if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &d)) return std::nullopt;
  return d.ftLastWriteTime;
}

namespace {
class Sha256 {
 public:
  Sha256() {
    if (BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) alg_ = nullptr;
    if (alg_ && BCryptCreateHash(alg_, &hash_, nullptr, 0, nullptr, 0, 0) != 0) hash_ = nullptr;
  }
  ~Sha256() {
    if (hash_) BCryptDestroyHash(hash_);
    if (alg_) BCryptCloseAlgorithmProvider(alg_, 0);
  }
  bool ok() const { return hash_ != nullptr; }
  void Update(const void* p, ULONG n) { BCryptHashData(hash_, static_cast<PUCHAR>(const_cast<void*>(p)), n, 0); }
  std::string Final() {
    UCHAR digest[32];
    if (BCryptFinishHash(hash_, digest, sizeof(digest), 0) != 0) return {};
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (UCHAR b : digest) {
      s += hex[b >> 4];
      s += hex[b & 15];
    }
    return s;
  }

 private:
  BCRYPT_ALG_HANDLE alg_ = nullptr;
  BCRYPT_HASH_HANDLE hash_ = nullptr;
};
}  // namespace

std::string Sha256File(const std::wstring& path, uint64_t max_bytes) {
  HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  if (f == INVALID_HANDLE_VALUE) return {};
  HandleCloser c{f};
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(f, &size) || static_cast<uint64_t>(size.QuadPart) > max_bytes) return {};
  Sha256 h;
  if (!h.ok()) return {};
  std::vector<char> buf(1 << 16);
  DWORD got = 0;
  while (ReadFile(f, buf.data(), static_cast<DWORD>(buf.size()), &got, nullptr) && got) h.Update(buf.data(), got);
  return h.Final();
}

std::string Sha256Bytes(const void* data, size_t len) {
  Sha256 h;
  if (!h.ok()) return {};
  h.Update(data, static_cast<ULONG>(len));
  return h.Final();
}

std::optional<std::string> ReadFileBytes(const std::wstring& path, size_t max_bytes) {
  HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         nullptr, OPEN_EXISTING, 0, nullptr);
  if (f == INVALID_HANDLE_VALUE) return std::nullopt;
  HandleCloser c{f};
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(f, &size) || static_cast<uint64_t>(size.QuadPart) > max_bytes) return std::nullopt;
  std::string out(static_cast<size_t>(size.QuadPart), '\0');
  DWORD got = 0;
  if (!out.empty() && (!ReadFile(f, out.data(), static_cast<DWORD>(out.size()), &got, nullptr))) return std::nullopt;
  out.resize(got);
  return out;
}

std::vector<DirEntry> ListDir(const std::wstring& dir) {
  std::vector<DirEntry> out;
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileExW((dir + L"\\*").c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr,
                              FIND_FIRST_EX_LARGE_FETCH);
  if (h == INVALID_HANDLE_VALUE) return out;
  do {
    if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
    DirEntry e;
    e.name = fd.cFileName;
    e.is_dir = fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    e.is_reparse = fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT;
    e.size = (static_cast<uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
    e.write_time = fd.ftLastWriteTime;
    out.push_back(std::move(e));
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  return out;
}

std::optional<DWORD> RegDword(HKEY root, const wchar_t* subkey, const wchar_t* value) {
  DWORD v = 0, size = sizeof(v);
  if (RegGetValueW(root, subkey, value, RRF_RT_REG_DWORD, nullptr, &v, &size) != ERROR_SUCCESS) return std::nullopt;
  return v;
}

std::optional<std::wstring> RegString(HKEY root, const wchar_t* subkey, const wchar_t* value) {
  DWORD size = 0;
  if (RegGetValueW(root, subkey, value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr, nullptr,
                   &size) != ERROR_SUCCESS)
    return std::nullopt;
  std::wstring s(size / sizeof(wchar_t) + 1, L'\0');
  if (RegGetValueW(root, subkey, value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr, s.data(),
                   &size) != ERROR_SUCCESS)
    return std::nullopt;
  s.resize(wcslen(s.c_str()));
  return s;
}

std::optional<std::vector<uint8_t>> RegBinary(HKEY root, const wchar_t* subkey, const wchar_t* value) {
  DWORD size = 0;
  if (RegGetValueW(root, subkey, value, RRF_RT_ANY, nullptr, nullptr, &size) != ERROR_SUCCESS) return std::nullopt;
  std::vector<uint8_t> v(size);
  if (RegGetValueW(root, subkey, value, RRF_RT_ANY, nullptr, v.data(), &size) != ERROR_SUCCESS) return std::nullopt;
  v.resize(size);
  return v;
}

std::vector<std::wstring> RegSubkeys(HKEY root, const wchar_t* subkey) {
  std::vector<std::wstring> out;
  HKEY k;
  if (RegOpenKeyExW(root, subkey, 0, KEY_ENUMERATE_SUB_KEYS, &k) != ERROR_SUCCESS) return out;
  wchar_t name[256];
  for (DWORD i = 0;; ++i) {
    DWORD n = static_cast<DWORD>(std::size(name));
    if (RegEnumKeyExW(k, i, name, &n, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
    out.emplace_back(name, n);
  }
  RegCloseKey(k);
  return out;
}

std::vector<std::wstring> RegValueNames(HKEY root, const wchar_t* subkey) {
  std::vector<std::wstring> out;
  HKEY k;
  if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS) return out;
  std::vector<wchar_t> name(32768);
  for (DWORD i = 0;; ++i) {
    DWORD n = static_cast<DWORD>(name.size());
    if (RegEnumValueW(k, i, name.data(), &n, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
    out.emplace_back(name.data(), n);
  }
  RegCloseKey(k);
  return out;
}

std::vector<ProcEntry> SnapshotProcesses() {
  std::vector<ProcEntry> out;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return out;
  HandleCloser c{snap};
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      out.push_back({pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile});
    } while (Process32NextW(snap, &pe));
  }
  return out;
}

std::map<DWORD, ProcEntry> SnapshotProcessMap() {
  std::map<DWORD, ProcEntry> m;
  for (auto& p : SnapshotProcesses()) m[p.pid] = p;
  return m;
}

std::wstring ProcessImagePath(DWORD pid) {
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h) return {};
  HandleCloser c{h};
  wchar_t buf[32768];
  DWORD n = static_cast<DWORD>(std::size(buf));
  return QueryFullProcessImageNameW(h, 0, buf, &n) ? std::wstring(buf, n) : std::wstring();
}

std::optional<std::wstring> ProcessCommandLine(DWORD pid) {
  const auto& api = nt::Get();
  if (!api.QueryInformationProcess) return std::nullopt;
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h) return std::nullopt;
  HandleCloser c{h};
  ULONG len = 0;
  api.QueryInformationProcess(h, nt::kProcessCommandLineInformation, nullptr, 0, &len);
  if (!len || len > (1u << 20)) return std::nullopt;
  std::vector<BYTE> buf(len);
  if (api.QueryInformationProcess(h, nt::kProcessCommandLineInformation, buf.data(), len, &len) < 0)
    return std::nullopt;
  auto* us = reinterpret_cast<UNICODE_STRING*>(buf.data());
  if (!us->Buffer) return std::wstring();
  return std::wstring(us->Buffer, us->Length / sizeof(wchar_t));
}

std::optional<bool> ProcessElevated(DWORD pid) {
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h) return std::nullopt;
  HandleCloser c{h};
  HANDLE tok = nullptr;
  if (!OpenProcessToken(h, TOKEN_QUERY, &tok)) return std::nullopt;
  HandleCloser t{tok};
  TOKEN_ELEVATION e{};
  DWORD n = 0;
  if (!GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &n)) return std::nullopt;
  return e.TokenIsElevated != 0;
}

uint64_t ProcessCreateTime(DWORD pid) {
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!h) return 0;
  HandleCloser c{h};
  FILETIME ct, et, kt, ut;
  if (!GetProcessTimes(h, &ct, &et, &kt, &ut)) return 0;
  return (static_cast<uint64_t>(ct.dwHighDateTime) << 32) | ct.dwLowDateTime;
}

// ---- Authenticode ----

namespace {

std::wstring SignerFromState(HANDLE state) {
  CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(state);
  if (!pd) return {};
  CRYPT_PROVIDER_SGNR* sg = WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);
  if (!sg || sg->csCertChain == 0 || !sg->pasCertChain || !sg->pasCertChain[0].pCert) return {};
  wchar_t name[512];
  DWORD n = CertGetNameStringW(sg->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name,
                               static_cast<DWORD>(std::size(name)));
  return n > 1 ? std::wstring(name) : std::wstring();
}

bool RunVerify(WINTRUST_DATA& wd, std::wstring& signer) {
  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  wd.cbStruct = sizeof(wd);
  wd.dwUIChoice = WTD_UI_NONE;
  wd.fdwRevocationChecks = WTD_REVOKE_NONE;
  wd.dwStateAction = WTD_STATEACTION_VERIFY;
  wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
  LONG st = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
  if (st == ERROR_SUCCESS) signer = SignerFromState(wd.hWVTStateData);
  wd.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
  return st == ERROR_SUCCESS;
}

// The SHA-256 catalog APIs are resolved at run time so the build does not depend on
// which SDK declares them.
using AcquireCtx2Fn = BOOL(WINAPI*)(HCATADMIN*, const GUID*, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
using CalcHash2Fn = BOOL(WINAPI*)(HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);

bool VerifyCatalog(const std::wstring& path, std::wstring& signer) {
  static HMODULE wt = LoadLibraryExW(L"wintrust.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!wt) return false;
  static auto acquire = reinterpret_cast<AcquireCtx2Fn>(GetProcAddress(wt, "CryptCATAdminAcquireContext2"));
  static auto calc = reinterpret_cast<CalcHash2Fn>(GetProcAddress(wt, "CryptCATAdminCalcHashFromFileHandle2"));
  if (!acquire || !calc) return false;

  HCATADMIN cat = nullptr;
  if (!acquire(&cat, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) return false;
  bool ok = false;
  HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                         OPEN_EXISTING, 0, nullptr);
  if (f != INVALID_HANDLE_VALUE) {
    DWORD size = 0;
    calc(cat, f, &size, nullptr, 0);
    std::vector<BYTE> hash(size ? size : 1);
    if (size && calc(cat, f, &size, hash.data(), 0)) {
      HCATINFO ci = CryptCATAdminEnumCatalogFromHash(cat, hash.data(), size, 0, nullptr);
      if (ci) {
        CATALOG_INFO info{};
        info.cbStruct = sizeof(info);
        if (CryptCATCatalogInfoFromContext(ci, &info, 0)) {
          std::wstring tag;
          static const wchar_t* hex = L"0123456789ABCDEF";
          for (DWORD i = 0; i < size; ++i) {
            tag += hex[hash[i] >> 4];
            tag += hex[hash[i] & 15];
          }
          WINTRUST_CATALOG_INFO wci{};
          wci.cbStruct = sizeof(wci);
          wci.pcwszCatalogFilePath = info.wszCatalogFile;
          wci.pcwszMemberFilePath = path.c_str();
          wci.pcwszMemberTag = tag.c_str();
          wci.pbCalculatedFileHash = hash.data();
          wci.cbCalculatedFileHash = size;
          wci.hCatAdmin = cat;
          WINTRUST_DATA wd{};
          wd.dwUnionChoice = WTD_CHOICE_CATALOG;
          wd.pCatalog = &wci;
          ok = RunVerify(wd, signer);
        }
        CryptCATAdminReleaseCatalogContext(cat, ci, 0);
      }
    }
    CloseHandle(f);
  }
  CryptCATAdminReleaseContext(cat, 0);
  return ok;
}

}  // namespace

SignerInfo GetSigner(const std::wstring& path) {
  static std::mutex mu;
  static std::map<std::wstring, SignerInfo> cache;
  std::wstring key = ToLower(path);
  {
    std::lock_guard<std::mutex> lock(mu);
    auto it = cache.find(key);
    if (it != cache.end()) return it->second;
  }
  SignerInfo info;
  if (!path.empty()) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();
    WINTRUST_DATA wd{};
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    std::wstring signer;
    if (RunVerify(wd, signer)) {
      info.signed_ok = true;
      info.signer = signer;
    } else if (VerifyCatalog(path, signer)) {
      info.signed_ok = true;
      info.catalog = true;
      info.signer = signer;
    }
  }
  std::lock_guard<std::mutex> lock(mu);
  cache[key] = info;
  return info;
}

int64_t NowUnix() { return static_cast<int64_t>(std::time(nullptr)); }

std::string UnixToIso(int64_t t) {
  std::time_t tt = static_cast<std::time_t>(t);
  std::tm tm{};
  gmtime_s(&tm, &tt);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

std::string FileTimeToIso(const FILETIME& ft) {
  uint64_t v = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
  return UnixToIso(static_cast<int64_t>(v / 10000000ULL) - 11644473600LL);
}

}  // namespace aegis::win
