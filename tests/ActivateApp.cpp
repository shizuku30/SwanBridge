#include <windows.h>
#include <shobjidl.h>
#include <winrt/base.h>
#include <iostream>

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3 || (std::wstring_view(argv[2]) != L"acceptance-mobike-profile" &&
        std::wstring_view(argv[2]) != L"acceptance-split-profile" &&
        std::wstring_view(argv[2]) != L"acceptance-rekey-profile" &&
        std::wstring_view(argv[2]) != L"acceptance-remove-rekey-profile")) return 2;
    try
    {
        winrt::init_apartment();
        const auto manager = winrt::create_instance<IApplicationActivationManager>(CLSID_ApplicationActivationManager);
        DWORD process = 0;
        winrt::check_hresult(manager->ActivateApplication(argv[1], argv[2], AO_NOERRORUI, &process));
        std::wcout << L"Application activated; process=" << process << L'\n';
        return 0;
    }
    catch (winrt::hresult_error const& error)
    {
        std::wcerr << L"Activation failed: " << error.message().c_str() << L'\n';
        return 1;
    }
}
