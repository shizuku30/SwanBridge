#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <iostream>
#include <stdexcept>
#include <functional>

using namespace winrt;
using namespace Windows::Foundation::Collections;

void Check(bool value, char const* description)
{
    if (!value) throw std::runtime_error(description);
    std::cout << "PASS " << description << '\n';
}

int main()
{
    init_apartment(apartment_type::multi_threaded);
    try
    {
        auto transient = single_threaded_observable_map<hstring, hstring>();
        auto expired = make_weak(transient);
        auto weakSubscription = transient.MapChanged(auto_revoke, [](auto const&, auto const&) {});
        transient = nullptr;
        Check(!expired.get(), "an auto-revoked subscription alone does not keep its source alive");
        weakSubscription.revoke();
        Check(!weakSubscription, "a revoker tolerates an already released source");

        struct Observer
        {
            IObservableMap<hstring, hstring> source{ nullptr };
            IObservableMap<hstring, hstring>::MapChanged_revoker subscription;
        };
        Observer observer;
        int notifications = 0;
        auto temporary = single_threaded_observable_map<hstring, hstring>();
        auto live = make_weak(temporary);
        observer.source = temporary;
        observer.subscription = observer.source.MapChanged(auto_revoke,
            [&notifications](auto const&, auto const&) { ++notifications; });
        temporary = nullptr;
        Check(!!live.get(), "the observer owns a strong reference to its event source");
        observer.source.Insert(L"Language", L"en-US");
        Check(notifications == 1, "language notification remains callable after the temporary reference is released");
        observer.subscription.revoke();
        observer.source.Insert(L"Language", L"zh-Hans");
        Check(notifications == 1, "revocation stops delivery before the owner is released");
        observer.source = nullptr;
        Check(!live.get(), "the event source is released after revocation without leaking it");

        auto label = single_threaded_observable_map<hstring, hstring>();
        auto labelWeak = make_weak(label);
        std::function<void()> update = [label] { label.Insert(L"Text", L"Translated"); };
        label = nullptr;
        Check(!!labelWeak.get(), "a fixed binding owns its projected target independently of its original local variable");
        update();
        Check(labelWeak.get().Lookup(L"Text") == L"Translated", "a retained localization callback still updates its target");
        update = nullptr;
        Check(!labelWeak.get(), "releasing the callback also releases its fixed target");
        return 0;
    }
    catch (std::exception const& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
