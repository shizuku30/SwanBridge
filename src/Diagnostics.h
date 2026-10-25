#pragma once
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>

namespace swanbridge
{
    inline void RecordEvent(wchar_t const* event, wchar_t const* error = L"") noexcept
    {
        try
        {
            const auto values = winrt::Windows::Storage::ApplicationData::Current().LocalSettings().Values();
            values.Insert(L"LastEvent", winrt::box_value(event));
            if (*error) values.Insert(L"LastError", winrt::box_value(error));
            values.Insert(L"LastEventTime", winrt::box_value(winrt::clock::now()));
        }
        catch (...) {}
    }
}
