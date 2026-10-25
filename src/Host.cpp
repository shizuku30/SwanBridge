#include <windows.h>
#include <winrt/Windows.ApplicationModel.Core.h>
#include <winrt/Windows.Foundation.h>

struct FactoryProvider : winrt::implements<FactoryProvider, winrt::Windows::Foundation::IGetActivationFactory>
{
    using Activate = HRESULT (__stdcall*)(void*, void**);
    Activate activate;

    FactoryProvider()
    {
        // Keep the only plugin implementation loaded for the host process lifetime.
        const auto module = LoadPackagedLibrary(L"SwanBridge.Plugin.dll", 0);
        if (!module) winrt::throw_last_error();
        activate = reinterpret_cast<Activate>(GetProcAddress(module, "DllGetActivationFactory"));
        if (!activate) winrt::throw_last_error();
    }

    winrt::Windows::Foundation::IInspectable GetActivationFactory(winrt::hstring const& classId) const
    {
        winrt::Windows::Foundation::IActivationFactory factory{ nullptr };
        winrt::check_hresult(activate(winrt::get_abi(classId), winrt::put_abi(factory)));
        return factory;
    }
};

int __stdcall wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    winrt::init_apartment(winrt::apartment_type::multi_threaded);
    winrt::Windows::ApplicationModel::Core::CoreApplication::RunWithActivationFactories(winrt::make<FactoryProvider>());
}
