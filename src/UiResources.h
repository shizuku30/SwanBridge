#pragma once
#include <winrt/Windows.ApplicationModel.Resources.Core.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.System.UserProfile.h>
#include "LanguagePolicy.h"

namespace swanbridge
{
    struct UiResources
    {
        winrt::Windows::ApplicationModel::Resources::Core::ResourceContext context;
        winrt::Windows::ApplicationModel::Resources::Core::ResourceMap map{
            winrt::Windows::ApplicationModel::Resources::Core::ResourceManager::Current().MainResourceMap().GetSubtree(L"Resources") };
        winrt::hstring language;

        UiResources() { Refresh(); }

        bool Refresh()
        {
            const auto preferred = winrt::Windows::System::UserProfile::GlobalizationPreferences::Languages();
            const winrt::hstring selected = SelectUiLanguage(preferred.Size() ? std::wstring_view(preferred.GetAt(0)) : std::wstring_view());
            if (language == selected) return false;
            context.Languages(winrt::single_threaded_vector<winrt::hstring>({ selected }).GetView());
            language = selected;
            return true;
        }

        winrt::hstring Get(wchar_t const* key) const { return map.GetValue(key, context).ValueAsString(); }
    };

    inline winrt::hstring LocalizedProviderError(winrt::hstring const& diagnostic) noexcept
    {
        try
        {
            const std::wstring_view message(diagnostic);
            wchar_t const* key = nullptr;
            if (message.starts_with(L"SB1001:")) key = L"ProviderEngineUnavailable";
            else if (message.starts_with(L"SB1002:")) key = L"ProviderInvalidConfiguration";
            else if (message.starts_with(L"SB2007:")) key = L"ProviderInitializationFailed";
            else if (message.starts_with(L"SB2002:")) key = L"ProviderAuthenticationFailed";
            else if (message.starts_with(L"SB2003:")) key = L"ProviderTransportFailed";
            else if (message.starts_with(L"SB2004:")) key = L"ProviderSetupFailed";
            else if (message.starts_with(L"SB3101:")) key = L"ProviderMobikeFailed";
            else if (message.starts_with(L"SB3001:")) key = L"ProviderSaExpired";
            if (key) return UiResources().Get(key);
        }
        catch (...) { }
        return diagnostic;
    }
}
