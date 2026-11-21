#include "eventlog.h"

#include <windows.h>
#include <winevt.h>

#include <vector>

namespace aegis::evt {

int Query(const std::wstring& channel, const std::wstring& xpath, int max_events,
          const std::function<void(const std::wstring& xml)>& fn) {
  EVT_HANDLE q = EvtQuery(nullptr, channel.c_str(), xpath.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);
  if (!q) return -1;
  int seen = 0;
  EVT_HANDLE batch[64];
  std::vector<wchar_t> buf(1 << 15);
  while (seen < max_events) {
    DWORD got = 0;
    if (!EvtNext(q, static_cast<DWORD>(std::size(batch)), batch, 5000, 0, &got)) break;
    for (DWORD i = 0; i < got; ++i) {
      DWORD used = 0, props = 0;
      if (!EvtRender(nullptr, batch[i], EvtRenderEventXml, static_cast<DWORD>(buf.size() * sizeof(wchar_t)),
                     buf.data(), &used, &props)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
          buf.resize(used / sizeof(wchar_t) + 1);
          if (!EvtRender(nullptr, batch[i], EvtRenderEventXml, static_cast<DWORD>(buf.size() * sizeof(wchar_t)),
                         buf.data(), &used, &props))
            used = 0;
        } else {
          used = 0;
        }
      }
      if (used && seen < max_events) {
        ++seen;
        fn(std::wstring(buf.data()));
      }
      EvtClose(batch[i]);
    }
  }
  EvtClose(q);
  return seen;
}

std::wstring IdWithinDays(int event_id, int days) { return IdsWithinDays({event_id}, days); }

std::wstring IdsWithinDays(std::initializer_list<int> ids, int days) {
  std::wstring cond;
  for (int id : ids) {
    if (!cond.empty()) cond += L" or ";
    cond += L"EventID=" + std::to_wstring(id);
  }
  long long ms = static_cast<long long>(days) * 86400000LL;
  return L"*[System[(" + cond + L") and TimeCreated[timediff(@SystemTime) <= " + std::to_wstring(ms) + L"]]]";
}

std::wstring SystemTime(const std::wstring& xml) {
  auto p = xml.find(L"SystemTime=");
  if (p == std::wstring::npos || p + 12 >= xml.size()) return {};
  wchar_t q = xml[p + 11];
  auto e = xml.find(q, p + 12);
  return e == std::wstring::npos ? std::wstring() : xml.substr(p + 12, e - p - 12);
}

std::wstring Element(const std::wstring& xml, const std::wstring& tag, const std::wstring& after) {
  size_t start = 0;
  if (!after.empty()) {
    start = xml.find(after);
    if (start == std::wstring::npos) return {};
  }
  std::wstring open = L"<" + tag + L">";
  auto p = xml.find(open, start);
  if (p == std::wstring::npos) return {};
  p += open.size();
  auto e = xml.find(L"</" + tag + L">", p);
  return e == std::wstring::npos ? std::wstring() : xml.substr(p, e - p);
}

}  // namespace aegis::evt
