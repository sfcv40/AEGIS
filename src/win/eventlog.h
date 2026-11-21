// Small wrapper over the Windows Event Log API (wevtapi).
#pragma once

#include <functional>
#include <string>

namespace aegis::evt {

// Runs `xpath` on `channel`, newest first, and calls `fn` with each event's XML.
// Returns the number of events visited, or -1 if the channel could not be queried.
int Query(const std::wstring& channel, const std::wstring& xpath, int max_events,
          const std::function<void(const std::wstring& xml)>& fn);

// "*[System[(EventID=N) and TimeCreated[timediff(@SystemTime) <= ms]]]"
std::wstring IdWithinDays(int event_id, int days);
std::wstring IdsWithinDays(std::initializer_list<int> ids, int days);

// <TimeCreated SystemTime='...'/> from the System section.
std::wstring SystemTime(const std::wstring& xml);
// Text of the first <tag>...</tag> at or after `after` (an earlier substring).
std::wstring Element(const std::wstring& xml, const std::wstring& tag, const std::wstring& after = L"");

}  // namespace aegis::evt
