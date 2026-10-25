#pragma once
#include <string>
#include <string_view>

namespace swanbridge
{
    inline wchar_t const* SelectUiLanguage(std::wstring_view language)
    {
        std::wstring normalized(language);
        for (auto& ch : normalized) if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch + L'a' - L'A');
        if (!normalized.starts_with(L"zh-")) return L"en-US";
        const auto next = normalized.find(L'-', 3);
        const auto qualifier = normalized.substr(3, next == std::wstring::npos ? next : next - 3);
        if (qualifier == L"hans") return L"zh-Hans";
        if (qualifier == L"cn" || qualifier == L"sg") return L"zh-Hans";
        return L"en-US";
    }

    inline std::wstring FormatUiText(std::wstring value, std::wstring_view argument)
    {
        const auto position = value.find(L"{0}");
        if (position != std::wstring::npos) value.replace(position, 3, argument);
        return value;
    }
}
