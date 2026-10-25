#include <windows.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.ApplicationModel.Activation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Networking.Vpn.h>
#include <winrt/Windows.Networking.h>
#include <winrt/Windows.Networking.Sockets.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Security.Cryptography.DataProtection.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Storage.Streams.h>
#include <winrt/Windows.System.h>
#include <winrt/Windows.UI.h>
#include <winrt/Windows.UI.Core.h>
#include <winrt/Windows.UI.ViewManagement.h>
#include <winrt/Windows.UI.Xaml.h>
#include <winrt/Windows.UI.Xaml.Automation.h>
#include <winrt/Windows.UI.Xaml.Controls.h>
#include <winrt/Windows.UI.Xaml.Controls.Primitives.h>
#include <winrt/Windows.UI.Xaml.Media.h>
#include <winrt/Windows.UI.Xaml.Media.Imaging.h>
#include <winrt/Windows.UI.Xaml.Markup.h>
#include <winrt/Windows.UI.Xaml.Interop.h>
#include "ProfileConfiguration.h"
#include "ProfileEditorState.h"
#include "ThemePolicy.h"
#include "UiResources.h"
#include <functional>

using namespace winrt;
using namespace Windows::ApplicationModel;
using namespace Windows::ApplicationModel::Activation;
using namespace Windows::Foundation;
using namespace Windows::Networking::Vpn;
using namespace Windows::Storage;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;

namespace swanbridge
{
    struct App : ApplicationT<App>
    {
        struct Record { VpnPlugInProfile profile{ nullptr }; };
        std::vector<Record> records;
        ListView connections{ nullptr };
        SplitView split{ nullptr };
        Pivot tabs{ nullptr };
        TextBox name{ nullptr }, server{ nullptr }, localId{ nullptr }, remoteId{ nullptr };
        TextBox mtu{ nullptr }, natPort{ nullptr }, splitRoutes{ nullptr }, customDns{ nullptr };
        ComboBox localType{ nullptr }, remoteType{ nullptr }, ike{ nullptr }, esp{ nullptr };
        ComboBox dpd{ nullptr }, keepAlive{ nullptr }, retransmitTimeout{ nullptr }, retransmitTries{ nullptr };
        ComboBox keyingTries{ nullptr }, childLifetime{ nullptr }, connectTimeout{ nullptr }, fragmentation{ nullptr }, mobility{ nullptr };
        ComboBox routeMode{ nullptr }, dnsMode{ nullptr };
        ComboBox ikeRekey{ nullptr }, childRekeyPercent{ nullptr }, rekeyJitter{ nullptr };
        ToggleSwitch excludeLocal{ nullptr };
        PasswordBox psk{ nullptr };
        TextBlock status{ nullptr }, heading{ nullptr }, connectionState{ nullptr }, passwordHelp{ nullptr };
        Button create{ nullptr }, add{ nullptr }, refresh{ nullptr }, defaults{ nullptr }, menu{ nullptr };
        int currentIndex = -1;
        bool busy = false, loading = true, selecting = false, readOnly = false;
        hstring loadedXml, credentialReference;
        ProfileEditorState savedEditor;
        Windows::UI::Xaml::Controls::Page viewRoot{ nullptr };
        Windows::UI::ViewManagement::UISettings appearance;
        Windows::UI::ViewManagement::UISettings::ColorValuesChanged_revoker themeChanged;
        Window::Activated_revoker themeActivated;
        Windows::ApplicationModel::Resources::Core::ResourceContext languageContext{ nullptr };
        Windows::Foundation::Collections::IObservableMap<hstring, hstring> languageQualifiers{ nullptr };
        Windows::Foundation::Collections::IObservableMap<hstring, hstring>::MapChanged_revoker languageChanged;
        UiResources strings;
        std::vector<std::function<void()>> localized;
        hstring statusKey = L"UI_LoadingConnections", statusArgument;
        bool statusError = false, unsupportedProfile = false;
        struct UiError { wchar_t const* key; hstring argument; };

        hstring T(wchar_t const* key) const
        {
            return std::wstring_view(key).starts_with(L"UI_") ? strings.Get(key) : hstring(key);
        }

        template<typename Target, typename Setter>
        void Bind(Target const& target, wchar_t const* key, Setter setter)
        {
            // XAML's internal tree references do not keep every projected weak reference resolvable.
            auto update = [this, target, key, setter] { setter(target, T(key)); };
            update(); localized.emplace_back(std::move(update));
        }

        template<typename Target, typename Setter>
        void BindTransient(Target const& target, wchar_t const* key, Setter setter)
        {
            auto update = [this, weak = make_weak(target), key, setter]
                { if (auto value = weak.get()) setter(value, T(key)); };
            update(); localized.emplace_back(std::move(update));
        }

        TextBlock LocalText(wchar_t const* key, double size = 13, bool subdued = false)
        {
            auto text = Text(T(key), size, subdued);
            Bind(text, key, [](TextBlock const& target, hstring const& value) { target.Text(value); });
            return text;
        }

        void BindTip(Control const& target, wchar_t const* key)
        {
            Bind(target, key, [](Control const& control, hstring const& value) { SetTip(control, value); });
        }

        void RefreshProfileText()
        {
            if (!status || !create) return;
            const bool existing = currentIndex >= 0 && currentIndex < static_cast<int>(records.size());
            heading.Text(existing ? records[currentIndex].profile.ProfileName() : T(L"UI_NewConnection"));
            passwordHelp.Text(T(existing ? L"UI_KeepPskHelp" : L"UI_NewPskHelp"));
            connectionState.Text(!existing ? hstring(L"IKEv2 / PSK / strongSwan") :
                unsupportedProfile ? T(L"UI_UnsupportedProfile") :
                State(records[currentIndex].profile) + (readOnly ? T(L"UI_ReadOnlySuffix") : hstring()));
            SetCommandLabel(create, existing ? L"UI_SaveChanges" : L"UI_CreateConnection");
            for (uint32_t i = 0; i < records.size() && i < connections.Items().Size(); ++i)
                connections.Items().GetAt(i).as<ListViewItem>().Content().as<StackPanel>().Children()
                    .GetAt(1).as<TextBlock>().Text(State(records[i].profile));
        }

        void RefreshSystemLanguage()
        {
            if (!strings.Refresh()) return;
            if (viewRoot) viewRoot.Language(strings.language);
            for (auto const& update : localized) update();
            RefreshChoiceLabels();
            RefreshProfileText(); RenderStatus();
        }

        void RefreshChoiceLabels()
        {
            const bool previous = loading; loading = true;
            for (auto const& combo : {localType, remoteType, ike, esp, dpd, keepAlive, retransmitTimeout, retransmitTries,
                keyingTries, childLifetime, ikeRekey, childRekeyPercent, rekeyJitter, connectTimeout, fragmentation, mobility, routeMode, dnsMode})
            {
                const auto selected = combo.SelectedIndex();
                if (selected < 0) continue;
                // Re-select the same item to invalidate XAML's cached collapsed label.
                combo.IsDropDownOpen(false); combo.SelectedIndex(-1); combo.SelectedIndex(selected);
            }
            loading = previous;
        }

        void WatchSystemLanguage()
        {
            const auto dispatcher = Window::Current().Dispatcher();
            // The revoker is weak; keep both notification owners alive until after it is revoked.
            languageContext = Windows::ApplicationModel::Resources::Core::ResourceContext::GetForCurrentView();
            languageQualifiers = languageContext.QualifierValues();
            languageChanged = languageQualifiers.MapChanged(auto_revoke, [weak = get_weak(), dispatcher](auto const&, auto const&)
                {
                    (void)dispatcher.RunAsync(Windows::UI::Core::CoreDispatcherPriority::Normal,
                        [weak] { if (auto self = weak.get()) self->RefreshSystemLanguage(); });
                });
        }

        void ApplySystemTheme()
        {
            if (!viewRoot) return;
            const auto foreground = appearance.GetColorValue(Windows::UI::ViewManagement::UIColorType::Foreground);
            const auto theme = SystemPaletteIsDark(foreground.R, foreground.G, foreground.B) ? ElementTheme::Dark : ElementTheme::Light;
            if (viewRoot.RequestedTheme() != theme) viewRoot.RequestedTheme(theme);
            if (const auto xamlRoot = viewRoot.XamlRoot())
                for (auto const& popup : Windows::UI::Xaml::Media::VisualTreeHelper::GetOpenPopupsForXamlRoot(xamlRoot))
                    if (auto child = popup.Child().try_as<FrameworkElement>(); child && child.RequestedTheme() != theme)
                        child.RequestedTheme(theme);
        }

        void WatchSystemTheme()
        {
            const auto dispatcher = Window::Current().Dispatcher();
            themeChanged = appearance.ColorValuesChanged(auto_revoke,
                [weak = get_weak(), dispatcher](auto const&, auto const&)
                {
                    (void)dispatcher.RunAsync(Windows::UI::Core::CoreDispatcherPriority::Normal,
                        [weak] { if (auto self = weak.get()) self->ApplySystemTheme(); });
                });
            themeActivated = Window::Current().Activated(auto_revoke,
                [weak = get_weak()](auto const&, auto const&)
                { if (auto self = weak.get()) { self->ApplySystemTheme(); self->RefreshSystemLanguage(); } });
            ApplySystemTheme();
        }

        static void FollowOwnerTheme(FrameworkElement const& popup, FrameworkElement const& owner)
        {
            popup.RequestedTheme(owner.ActualTheme());
            owner.ActualThemeChanged([weak = make_weak(popup)](FrameworkElement const& sender, auto const&)
                { if (auto target = weak.get()) target.RequestedTheme(sender.ActualTheme()); });
        }

        static TextBlock Text(hstring const& value, double size = 13, bool subdued = false)
        {
            TextBlock text;
            text.Text(value); text.FontSize(size); text.TextWrapping(TextWrapping::Wrap);
            if (subdued) text.Opacity(0.68);
            return text;
        }

        static void SetTip(DependencyObject const& target, hstring const& value)
        {
            auto content = Text(value, 13); content.MaxWidth(320);
            auto tip = ToolTipService::GetToolTip(target).try_as<ToolTip>();
            if (!tip)
            {
                tip = ToolTip(); FollowOwnerTheme(tip, target.as<FrameworkElement>());
                ToolTipService::SetToolTip(target, tip);
            }
            tip.Content(content);
            Windows::UI::Xaml::Automation::AutomationProperties::SetHelpText(target, value);
        }

        void Labeled(StackPanel const& parent, wchar_t const* label, Control const& control)
        {
            StackPanel field; field.Spacing(4);
            Grid caption; caption.ColumnDefinitions().Append(ColumnDefinition());
            ColumnDefinition action; action.Width(GridLength{ 0, GridUnitType::Auto }); caption.ColumnDefinitions().Append(action);
            auto text = LocalText(label); text.VerticalAlignment(VerticalAlignment::Center); caption.Children().Append(text);
            Bind(control, label, [](Control const& target, hstring const& value)
                { Windows::UI::Xaml::Automation::AutomationProperties::SetName(target, value); });
            field.Children().Append(caption); field.Children().Append(control);
            control.Tag(caption); field.Tag(control); parent.Children().Append(field);
        }

        void Help(StackPanel const& parent, wchar_t const* key)
        {
            const auto control = parent.Children().GetAt(parent.Children().Size() - 1).as<FrameworkElement>().Tag().as<Control>();
            const auto caption = control.Tag().as<Grid>();
            auto info = IconButton(L"UI_ShowHelp", Symbol::Help, 24);
            BindTip(info, key); BindTip(control, key);
            auto updateName = [this, weak = make_weak(info), owner = make_weak(control)]
            {
                if (auto button = weak.get()) if (auto target = owner.get())
                    Windows::UI::Xaml::Automation::AutomationProperties::SetName(button,
                        Windows::UI::Xaml::Automation::AutomationProperties::GetName(target) + T(L"UI_HelpSuffix"));
            };
            updateName(); localized.emplace_back(std::move(updateName));
            Flyout flyout; auto content = LocalText(key, 13); content.MaxWidth(320); flyout.Content(content); info.Flyout(flyout);
            flyout.Opening([weak = make_weak(info)](IInspectable const& sender, IInspectable const&)
            {
                if (auto owner = weak.get())
                {
                    Style style(xaml_typename<FlyoutPresenter>());
                    style.Setters().Append(Setter(FrameworkElement::RequestedThemeProperty(), box_value(owner.ActualTheme())));
                    sender.as<Flyout>().FlyoutPresenterStyle(style);
                }
            });
            Grid::SetColumn(info, 1); caption.Children().Append(info);
        }

        TextBox Field(StackPanel const& parent, wchar_t const* label, wchar_t const* hint = L"")
        {
            TextBox field;
            field.MaxLength(253);
            Bind(field, hint, [](TextBox const& target, hstring const& value) { target.PlaceholderText(value); });
            field.HorizontalAlignment(HorizontalAlignment::Stretch);
            Labeled(parent, label, field); return field;
        }

        ComboBox Choice(StackPanel const& parent, wchar_t const* label,
            std::initializer_list<std::pair<wchar_t const*, wchar_t const*>> choices)
        {
            ComboBox combo;
            combo.HorizontalAlignment(HorizontalAlignment::Stretch);
            combo.HorizontalContentAlignment(HorizontalAlignment::Stretch);
            for (auto const& entry : choices)
            {
                ComboBoxItem item; item.Tag(box_value(entry.second));
                Bind(item, entry.first, [](ComboBoxItem const& target, hstring const& value) { target.Content(box_value(value)); });
                combo.Items().Append(item);
            }
            combo.SelectedIndex(0);
            Labeled(parent, label, combo); return combo;
        }

        static hstring Value(ComboBox const& combo)
        {
            const auto item = combo.SelectedItem().try_as<ComboBoxItem>();
            if (!item) throw UiError{L"UI_InvalidChoice"};
            return unbox_value<hstring>(item.Tag());
        }

        static std::uint32_t Number(hstring const& value, wchar_t const* message)
        {
            std::uint32_t parsed;
            if (!ParseUnsigned(value.c_str(), parsed)) throw UiError{message};
            return parsed;
        }

        static std::uint32_t ValueNumber(ComboBox const& combo) { return Number(Value(combo), L"UI_InvalidOption"); }

        void Select(ComboBox const& combo, hstring const& value)
        {
            for (uint32_t i = 0; i < combo.Items().Size(); ++i)
                if (unbox_value<hstring>(combo.Items().GetAt(i).as<ComboBoxItem>().Tag()) == value)
                { combo.SelectedIndex(static_cast<int>(i)); return; }
            ComboBoxItem item; item.Tag(box_value(value));
            auto update = [this, weak = make_weak(item), value]
                { if (auto target = weak.get()) target.Content(box_value(T(L"UI_CustomValue") + value)); };
            update(); localized.emplace_back(std::move(update));
            combo.Items().Append(item); combo.SelectedIndex(static_cast<int>(combo.Items().Size() - 1));
        }

        static Grid Icon(Symbol symbol)
        {
            FontIcon icon; icon.FontSize(16); icon.IsTextScaleFactorEnabled(false);
            icon.FontFamily(Windows::UI::Xaml::Media::FontFamily(L"Segoe MDL2 Assets"));
            switch (symbol)
            {
            case Symbol::Add: icon.Glyph(L"\uE710"); break;
            case Symbol::Refresh: icon.Glyph(L"\uE72C"); break;
            case Symbol::Setting: icon.Glyph(L"\uE713"); break;
            case Symbol::Save: icon.Glyph(L"\uE74E"); break;
            case Symbol::Help: icon.Glyph(L"\uE897"); break;
            case Symbol::GlobalNavigationButton: icon.Glyph(L"\uE700"); break;
            default: throw hresult_invalid_argument(L"Unsupported button icon.");
            }
            icon.HorizontalAlignment(HorizontalAlignment::Center); icon.VerticalAlignment(VerticalAlignment::Center);
            Grid slot; slot.Width(20); slot.Height(20);
            slot.HorizontalAlignment(HorizontalAlignment::Center); slot.VerticalAlignment(VerticalAlignment::Center);
            slot.Children().Append(icon); return slot;
        }

        static Button SizedButton(double width, double height)
        {
            Button button; button.MinWidth(0); button.MinHeight(0); button.Width(width); button.Height(height);
            button.Padding(Thickness{ 0 }); button.BorderThickness(Thickness{ 1 }); button.UseLayoutRounding(true);
            button.HorizontalContentAlignment(HorizontalAlignment::Center); button.VerticalContentAlignment(VerticalAlignment::Center);
            return button;
        }

        Button IconButton(wchar_t const* label, Symbol symbol, double edge = 36)
        {
            auto button = SizedButton(edge, edge); button.Content(Icon(symbol));
            BindTip(button, label);
            Bind(button, label, [](Button const& target, hstring const& value)
                { Windows::UI::Xaml::Automation::AutomationProperties::SetName(target, value); });
            return button;
        }

        void SetCommandLabel(Button const& button, wchar_t const* label)
        {
            button.Tag(box_value(hstring(label)));
            const auto value = T(label);
            button.Content().as<StackPanel>().Children().GetAt(1).as<TextBlock>().Text(value);
            SetTip(button, value);
            Windows::UI::Xaml::Automation::AutomationProperties::SetName(button, value);
        }

        Button Command(wchar_t const* label, Symbol symbol)
        {
            auto button = SizedButton(144, 36); button.Padding(Thickness{ 12, 0, 12, 0 });
            StackPanel content; content.Orientation(Orientation::Horizontal); content.Spacing(8);
            auto text = Text(T(label)); text.VerticalAlignment(VerticalAlignment::Center);
            text.TextWrapping(TextWrapping::NoWrap); text.TextTrimming(TextTrimming::CharacterEllipsis); text.MaxWidth(88);
            content.Children().Append(Icon(symbol)); content.Children().Append(text); button.Content(content);
            SetCommandLabel(button, label);
            localized.emplace_back([this, weak = make_weak(button)]
                { if (auto target = weak.get()) SetCommandLabel(target, unbox_value<hstring>(target.Tag()).c_str()); });
            return button;
        }

        StackPanel Page(wchar_t const* label, wchar_t const* title, wchar_t const* description)
        {
            StackPanel content; content.Spacing(10); content.Padding(Thickness{ 4, 8, 20, 24 });
            content.HorizontalAlignment(HorizontalAlignment::Stretch);
            content.Children().Append(LocalText(title, 18)); content.Children().Append(LocalText(description, 12, true));
            ScrollViewer scroll; scroll.HorizontalScrollBarVisibility(ScrollBarVisibility::Disabled);
            scroll.HorizontalScrollMode(ScrollMode::Disabled); scroll.HorizontalContentAlignment(HorizontalAlignment::Stretch);
            scroll.VerticalScrollBarVisibility(ScrollBarVisibility::Auto); scroll.Content(content);
            PivotItem item; Bind(item, label, [](PivotItem const& target, hstring const& value) { target.Header(box_value(value)); });
            item.HorizontalContentAlignment(HorizontalAlignment::Stretch);
            item.VerticalContentAlignment(VerticalAlignment::Stretch); item.Content(scroll); tabs.Items().Append(item); return content;
        }

        void Identity(StackPanel const& parent, bool local)
        {
            Grid row; ColumnDefinition kind; kind.Width(GridLength{ 144, GridUnitType::Pixel }); row.ColumnDefinitions().Append(kind);
            row.ColumnDefinitions().Append(ColumnDefinition());
            StackPanel types; types.Margin(Thickness{ 0, 0, 12, 0 });
            auto combo = Choice(types, L"UI_IdentityType", {{L"UI_IdentityName",L"1"},{L"UI_IdentityIpv4",L"2"}});
            StackPanel ids; auto field = Field(ids, local ? L"UI_LocalIdentity" : L"UI_RemoteIdentity");
            Grid::SetColumn(ids, 1); row.Children().Append(types); row.Children().Append(ids); row.Tag(field); parent.Children().Append(row);
            if (local) { localType = combo; localId = field; } else { remoteType = combo; remoteId = field; }
            Help(parent, local ? L"UI_LocalIdentityHelp" :
                L"UI_RemoteIdentityHelp");
        }

        void OnLaunched(LaunchActivatedEventArgs const& args)
        {
            if (viewRoot)
            {
                Window::Current().Activate();
#ifdef SWANBRIDGE_ACCEPTANCE_HOOKS
                if (args.Arguments() == L"acceptance-remove-rekey-profile") { RemoveRekeyProfile(); return; }
                if (args.Arguments() == L"acceptance-mobike-profile" || args.Arguments() == L"acceptance-split-profile" || args.Arguments() == L"acceptance-rekey-profile")
                    PrepareMobikeProfile(args.Arguments() != L"acceptance-mobike-profile", args.Arguments() == L"acceptance-rekey-profile");
#endif
                return;
            }
            Windows::UI::ViewManagement::ApplicationView::GetForCurrentView().SetPreferredMinSize(Size{ 400, 500 });
            viewRoot = Windows::UI::Xaml::Markup::XamlReader::Load(
                LR"(<Page xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    Background="{ThemeResource ApplicationPageBackgroundThemeBrush}"
                    Foreground="{ThemeResource SystemControlForegroundBaseHighBrush}" />)").as<Windows::UI::Xaml::Controls::Page>();
            ApplySystemTheme(); viewRoot.Language(strings.language);
            Grid root; root.Padding(Thickness{ 16, 12, 16, 12 });
            for (int i = 0; i < 3; ++i)
            {
                RowDefinition row; row.Height(GridLength{ i == 1 ? 1.0 : 0.0, i == 1 ? GridUnitType::Star : GridUnitType::Auto });
                root.RowDefinitions().Append(row);
            }
            Grid header; header.Margin(Thickness{ 0, 0, 0, 12 }); header.ColumnDefinitions().Append(ColumnDefinition());
            ColumnDefinition tools; tools.Width(GridLength{ 0, GridUnitType::Auto }); header.ColumnDefinitions().Append(tools);
            StackPanel brand; brand.Orientation(Orientation::Horizontal); brand.Spacing(12);
            menu = IconButton(L"UI_ConnectionList", Symbol::GlobalNavigationButton); brand.Children().Append(menu);
            Image logo; logo.Width(32); logo.Height(32);
            logo.Source(Windows::UI::Xaml::Media::Imaging::BitmapImage(Uri(L"ms-appx:///Assets/Square44x44Logo.png")));
            brand.Children().Append(logo); brand.Children().Append(Text(L"SwanBridge VPN",20)); header.Children().Append(brand);
            auto windows = IconButton(L"UI_WindowsSettings", Symbol::Setting);
            windows.Click([](auto const&, auto const&) -> fire_and_forget
            {
                try { co_await Windows::System::Launcher::LaunchUriAsync(Uri(L"ms-settings:network-vpn")); } catch (...) {}
            });
            Grid::SetColumn(windows,1); header.Children().Append(windows); root.Children().Append(header);
            split = Windows::UI::Xaml::Markup::XamlReader::Load(
                LR"(<SplitView xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
                    PaneBackground="{ThemeResource SystemControlBackgroundChromeMediumLowBrush}" />)").as<SplitView>();
            split.OpenPaneLength(232); split.CompactPaneLength(0);
            Grid::SetRow(split,1); root.Children().Append(split);
            menu.Click([this](auto const&, auto const&) { split.IsPaneOpen(!split.IsPaneOpen()); });
            split.SizeChanged([this](auto const&, SizeChangedEventArgs const& args)
            {
                const bool compact = args.NewSize().Width < 820;
                split.DisplayMode(compact ? SplitViewDisplayMode::Overlay : SplitViewDisplayMode::Inline);
                split.IsPaneOpen(!compact); menu.Visibility(compact ? Visibility::Visible : Visibility::Collapsed);
            });
            Grid sidebar; sidebar.Padding(Thickness{ 12,12,12,12 });
            for (int i=0;i<3;++i)
            {
                RowDefinition row; row.Height(GridLength{ i == 1 ? 1.0 : 0.0, i == 1 ? GridUnitType::Star : GridUnitType::Auto });
                sidebar.RowDefinitions().Append(row);
            }
            Grid listHeader; listHeader.ColumnDefinitions().Append(ColumnDefinition());
            ColumnDefinition action; action.Width(GridLength{ 0, GridUnitType::Auto }); listHeader.ColumnDefinitions().Append(action);
            listHeader.Children().Append(LocalText(L"UI_Connections",16));
            StackPanel actions; actions.Orientation(Orientation::Horizontal); actions.Spacing(4);
            add = IconButton(L"UI_NewConnection", Symbol::Add); refresh = IconButton(L"UI_RefreshConnections", Symbol::Refresh);
            add.Click([this](auto const&, auto const&) { NewProfile(); });
            refresh.Click([this](auto const&, auto const&) { PublishExistingProfiles(true); });
            actions.Children().Append(add); actions.Children().Append(refresh); Grid::SetColumn(actions,1); listHeader.Children().Append(actions);
            sidebar.Children().Append(listHeader);
            connections = ListView(); connections.Margin(Thickness{ 0,12,0,12 });
            connections.SelectionChanged([this](auto const&, auto const&) { SelectProfile(); });
            Grid::SetRow(connections,1); sidebar.Children().Append(connections);
            auto scope = LocalText(L"UI_ProviderScope",12,true); Grid::SetRow(scope,2); sidebar.Children().Append(scope); split.Pane(sidebar);
            Grid editor; editor.Padding(Thickness{ 16,0,0,0 });
            for (int i=0;i<3;++i)
            {
                RowDefinition row; row.Height(GridLength{ i == 1 ? 1.0 : 0.0, i == 1 ? GridUnitType::Star : GridUnitType::Auto });
                editor.RowDefinitions().Append(row);
            }
            StackPanel intro; intro.Spacing(4); heading = LocalText(L"UI_NewConnection",18); connectionState = Text(L"IKEv2 / PSK / strongSwan",12,true);
            intro.Children().Append(heading); intro.Children().Append(connectionState); editor.Children().Append(intro);
            tabs = Pivot(); tabs.Margin(Thickness{ -12,4,0,0 }); Grid::SetRow(tabs,1); editor.Children().Append(tabs);
            auto basic = Page(L"UI_Basic",L"UI_BasicTitle",L"UI_BasicDescription");
            name = Field(basic,L"UI_ConnectionName",L"SwanBridge"); name.MaxLength(128);
            server = Field(basic,L"UI_ServerAddress",L"vpn.example.com");
            Help(basic,L"UI_ServerHelp");
            Identity(basic,true); Identity(basic,false);
            psk = PasswordBox(); psk.MaxLength(1024);
            psk.PasswordRevealMode(PasswordRevealMode::Hidden); Labeled(basic,L"UI_Psk",psk);
            passwordHelp = LocalText(L"UI_PskProtected",12,true); basic.Children().Append(passwordHelp);
            auto security = Page(L"UI_Security",L"UI_SecurityTitle",L"UI_SecurityDescription");
            ike = Choice(security,L"UI_IkeProposal",{{L"UI_IkeRecommended",L"aes256-sha256-modp2048"},
                {L"AES-128 / SHA-256 / DH14",L"aes128-sha256-modp2048"},{L"AES-192 / SHA-256 / DH14",L"aes192-sha256-modp2048"},
                {L"AES-256 / SHA-256 / DH15",L"aes256-sha256-modp3072"}});
            Help(security,L"UI_IkeHelp");
            esp = Choice(security,L"UI_EspProposal",{{L"UI_EspRecommended",L"aes256-sha256"},
                {L"AES-128 / SHA-256",L"aes128-sha256"},{L"AES-192 / SHA-256",L"aes192-sha256"}});
            Help(security,L"UI_EspHelp");
            fragmentation = Choice(security,L"UI_Fragmentation",{{L"UI_EnabledRecommended",L"1"},{L"UI_Disabled",L"0"}});
            Help(security,L"UI_FragmentationHelp");
            auto encapsulation = Choice(security,L"UI_Encapsulation",{{L"UI_ForcedUdp",L"1"}}); encapsulation.IsEnabled(false);
            Help(security,L"UI_EncapsulationHelp");
            mobility = Choice(security,L"MOBIKE",{{L"UI_MobikeDisabled",L"0"},{L"UI_MobikeEnabled",L"1"}});
            Help(security,L"UI_MobikeHelp");
            auto lifetime = Page(L"UI_Connections",L"UI_LifetimeTitle",L"UI_LifetimeDescription");
            dpd = Choice(lifetime,L"UI_Dpd",{{L"UI_Seconds20Recommended",L"20"},{L"UI_Seconds10",L"10"},{L"UI_Seconds30",L"30"},{L"UI_Seconds60",L"60"},{L"UI_DisableProbing",L"0"}});
            Help(lifetime,L"UI_DpdHelp");
            keepAlive = Choice(lifetime,L"UI_KeepAlive",{{L"UI_Seconds15Recommended",L"15"},{L"UI_Seconds10",L"10"},{L"UI_Seconds20",L"20"},{L"UI_Seconds30",L"30"},{L"UI_Seconds60",L"60"}});
            Help(lifetime,L"UI_KeepAliveHelp");
            retransmitTimeout = Choice(lifetime,L"UI_RetransmitTimeout",{{L"UI_Seconds1Default",L"1"},{L"UI_Seconds2",L"2"},{L"UI_Seconds3",L"3"},{L"UI_Seconds5Latency",L"5"},{L"UI_Seconds10",L"10"}});
            Help(lifetime,L"UI_RetransmitTimeoutHelp");
            retransmitTries = Choice(lifetime,L"UI_RetransmitTries",{{L"UI_Tries3Default",L"3"},{L"UI_Tries4",L"4"},{L"UI_Tries5",L"5"},{L"UI_Tries6",L"6"},{L"UI_Tries8",L"8"}});
            Help(lifetime,L"UI_RetransmitTriesHelp");
            keyingTries = Choice(lifetime,L"UI_KeyingTries",{{L"UI_Tries1Default",L"1"},{L"UI_Tries2",L"2"},{L"UI_Tries3",L"3"},{L"UI_Tries6",L"6"}});
            Help(lifetime,L"UI_KeyingTriesHelp");
            connectTimeout = Choice(lifetime,L"UI_ConnectTimeout",{{L"UI_Seconds25Default",L"25"},{L"UI_Seconds30",L"30"},{L"UI_Seconds60",L"60"},{L"UI_Seconds90",L"90"},{L"UI_Seconds120",L"120"}});
            Help(lifetime,L"UI_ConnectTimeoutHelp");
            childLifetime = Choice(lifetime,L"UI_ChildLifetime",{{L"UI_Hours24Compatible",L"86400"},{L"UI_Hours1",L"3600"},{L"UI_Hours4",L"14400"},{L"UI_Hours8",L"28800"},{L"UI_Hours48",L"172800"}});
            Help(lifetime,L"UI_ChildLifetimeHelp");
            ikeRekey = Choice(lifetime,L"UI_IkeRekey",{{L"UI_Hours4Recommended",L"14400"},{L"UI_Hours1",L"3600"},{L"UI_Hours8",L"28800"},{L"UI_Hours24",L"86400"},{L"UI_DisableInitiation",L"0"}});
            Help(lifetime,L"UI_IkeRekeyHelp");
            childRekeyPercent = Choice(lifetime,L"UI_ChildRekey",{{L"UI_Lifetime90Recommended",L"90"},{L"UI_Lifetime80",L"80"},{L"UI_Lifetime95",L"95"},{L"UI_DisableInitiation",L"0"}});
            Help(lifetime,L"UI_ChildRekeyHelp");
            rekeyJitter = Choice(lifetime,L"UI_RekeyJitter",{{L"UI_Jitter5Recommended",L"5"},{L"UI_Jitter10",L"10"},{L"UI_Jitter20",L"20"},{L"UI_JitterNone",L"0"}});
            Help(lifetime,L"UI_RekeyJitterHelp");
            auto network = Page(L"UI_Network",L"UI_NetworkTitle",L"UI_NetworkDescription");
            natPort = Field(network,L"UI_NatPort",L"4500"); natPort.MaxLength(5);
            Help(network,L"UI_NatPortHelp");
            mtu = Field(network,L"UI_Mtu",L"1280"); mtu.MaxLength(4);
            Help(network,L"UI_MtuHelp");
            routeMode = Choice(network,L"UI_RouteMode",{{L"UI_FullTunnel",L"0"},{L"UI_SplitTunnel",L"1"}});
            splitRoutes = Field(network,L"UI_SplitRoutes",L"192.168.1.0/24");
            splitRoutes.AcceptsReturn(true); splitRoutes.Height(84); splitRoutes.MaxLength(4096);
            Help(network,L"UI_SplitRoutesHelp");
            excludeLocal = ToggleSwitch(); Labeled(network,L"UI_ExcludeLocal",excludeLocal);
            Bind(excludeLocal, L"UI_Excluded", [](ToggleSwitch const& target, hstring const& value) { target.OnContent(box_value(value)); });
            Bind(excludeLocal, L"UI_NotExcluded", [](ToggleSwitch const& target, hstring const& value) { target.OffContent(box_value(value)); });
            Help(network,L"UI_ExcludeLocalHelp");
            dnsMode = Choice(network,L"UI_DnsMode",{{L"UI_ServerDns",L"0"},{L"UI_CustomIpv4Dns",L"1"},{L"UI_SystemDns",L"2"}});
            Help(network,L"UI_DnsModeHelp");
            customDns = Field(network,L"UI_CustomDns",L"10.0.0.1, 8.8.8.8"); customDns.MaxLength(512);
            Help(network,L"UI_CustomDnsHelp");
            routeMode.SelectionChanged([this](auto const&, auto const&) { UpdateConditionalFields(); });
            dnsMode.SelectionChanged([this](auto const&, auto const&) { UpdateConditionalFields(); });
            StackPanel footer; footer.Orientation(Orientation::Horizontal); footer.Spacing(12); footer.Margin(Thickness{ 0,12,0,0 });
            create = Command(L"UI_CreateConnection",Symbol::Save); create.Click([this](auto const&,auto const&) { CreateProfile(); });
            defaults = Command(L"UI_ResetDefaults",Symbol::Refresh); defaults.Click([this](auto const&,auto const&) { RestoreDefaults(); });
            footer.Children().Append(create); footer.Children().Append(defaults); Grid::SetRow(footer,2); editor.Children().Append(footer); split.Content(editor);
            status = Text(T(L"UI_LoadingConnections"),12); status.Margin(Thickness{ 0,12,0,0 }); Grid::SetRow(status,2); root.Children().Append(status);
            viewRoot.Content(root); Window::Current().Content(viewRoot); WatchSystemTheme(); WatchSystemLanguage(); Window::Current().Activate(); ApplyOptions(ConnectionOptions{});
            savedEditor = CaptureEditor(); loading = false;
#ifdef SWANBRIDGE_ACCEPTANCE_HOOKS
            if (args.Arguments() == L"acceptance-remove-rekey-profile") { RemoveRekeyProfile(); return; }
            if (args.Arguments() == L"acceptance-mobike-profile" || args.Arguments() == L"acceptance-split-profile" || args.Arguments() == L"acceptance-rekey-profile")
            { PrepareMobikeProfile(args.Arguments() != L"acceptance-mobike-profile", args.Arguments() == L"acceptance-rekey-profile"); return; }
#else
            (void)args;
#endif
            PublishExistingProfiles();
        }

#ifdef SWANBRIDGE_ACCEPTANCE_HOOKS
        fire_and_forget RemoveRekeyProfile()
        {
            const auto lifetime = get_strong();
            const auto values = ApplicationData::Current().LocalSettings().Values();
            values.Insert(L"RekeyProfileCleanup", box_value(L"Running"));
            try
            {
                VpnManagementAgent agent;
                for (auto const& item : co_await agent.GetProfilesAsync())
                {
                    if (item.ProfileName() != L"SwanBridge-Acceptance-Rekey") continue;
                    const auto profile = item.try_as<VpnPlugInProfile>();
                    if (!profile || profile.VpnPluginPackageFamilyName() != Package::Current().Id().FamilyName() ||
                        profile.ConnectionStatus() != VpnManagementConnectionStatus::Disconnected ||
                        ParseProfile(profile.CustomConfiguration()).options.localId != L"swanbridge-rekey-acceptance")
                        throw hresult_invalid_argument(L"Rekey acceptance profile is active or not owned; not removed");
                    if (co_await agent.DeleteProfileAsync(profile) != VpnManagementErrorStatus::Ok)
                        throw hresult_error(E_FAIL, L"Windows refused test-profile cleanup");
                }
                values.Insert(L"RekeyProfileCleanup", box_value(L"Removed"));
            }
            catch (hresult_error const& error) { values.Insert(L"RekeyProfileCleanup", box_value(error.message())); }
            catch (...) { values.Insert(L"RekeyProfileCleanup", box_value(L"Failed")); }
            values.Insert(L"RekeyProfileCleanupAt", box_value(clock::now()));
            PublishExistingProfiles();
        }

        fire_and_forget PrepareMobikeProfile(bool splitAcceptance, bool rekeyAcceptance)
        {
            const auto lifetime = get_strong();
            const auto values = ApplicationData::Current().LocalSettings().Values();
            values.Insert(L"MobikeProfilePreparedAt", box_value(clock::now()));
            values.Insert(L"MobikeProfilePreparation", box_value(L"Running"));
            if (busy || HasEditorChanges(CaptureEditor(), savedEditor, !psk.Password().empty()))
            { values.Insert(L"MobikeProfilePreparation", box_value(L"Refused: editor is busy or contains unsaved changes")); co_return; }
            SetBusy(true);
            try
            {
                const auto testName = rekeyAcceptance ? L"SwanBridge-Acceptance-Rekey" :
                    (splitAcceptance ? L"SwanBridge-Acceptance-Split" : L"SwanBridge-Acceptance-MOBIKE");
                const auto family = Package::Current().Id().FamilyName();
                VpnManagementAgent agent;
                const auto profiles = co_await agent.GetProfilesAsync();
                VpnPlugInProfile source{nullptr}, target{nullptr};
                uint32_t candidates = 0;
                for (auto const& item : profiles)
                {
                    const auto profile = item.try_as<VpnPlugInProfile>();
                    if (item.ProfileName() == testName)
                    {
                        if (!profile || profile.VpnPluginPackageFamilyName() != family)
                            throw hresult_invalid_argument(L"Acceptance name belongs to another provider; not overwritten");
                        target = profile;
                    }
                    if (!profile || profile.VpnPluginPackageFamilyName() != family ||
                        std::wstring_view(profile.ProfileName()).starts_with(L"SwanBridge-Acceptance-")) continue;
                    try { ParseProfile(profile.CustomConfiguration(), std::wstring(profile.ProfileName())); }
                    catch (...) { continue; }
                    source = profile; ++candidates;
                }
                if (candidates != 1 || !source || source.ConnectionStatus() != VpnManagementConnectionStatus::Disconnected)
                    throw hresult_invalid_argument(L"Exactly one supported, disconnected non-acceptance profile is required");
                auto settings = ParseProfile(source.CustomConfiguration(), std::wstring(source.ProfileName()));
                settings.options.name = testName; settings.options.mobike = true;
                if (splitAcceptance)
                {
                    settings.options.routeMode = 1; settings.options.dnsMode = 2;
                    settings.options.excludeLocalSubnets = false;
                    settings.options.splitRoutes = L"10.77.0.1/32,192.0.2.222/32,8.8.8.8/32,1.1.1.1/32";
                    settings.options.customDns.clear();
                }
                if (rekeyAcceptance)
                {
                    settings.options.localId = L"swanbridge-rekey-acceptance";
                    settings.options.localIdType = SB_ID_FQDN;
                    settings.options.ikeRekey = 90; settings.options.childLifetime = 300;
                    settings.options.childRekeyPercent = 20; settings.options.rekeyJitter = 0;
                    hstring probeAddress;
                    for (auto const& pair : co_await Windows::Networking::Sockets::DatagramSocket::GetEndpointPairsAsync(
                        Windows::Networking::HostName(L"www.baidu.com"), L"443"))
                    {
                        if (pair.RemoteHostName().Type() == Windows::Networking::HostNameType::Ipv4)
                        { probeAddress = pair.RemoteHostName().CanonicalName(); break; }
                    }
                    std::uint32_t address;
                    if (probeAddress.empty() || !ParseIPv4(probeAddress.c_str(), address))
                        throw hresult_error(E_FAIL, L"No IPv4 address is available for the pinned acceptance HTTPS endpoint");
                    settings.options.splitRoutes.append(L",").append(probeAddress).append(L"/32");
                    values.Insert(L"RekeyHttpsAddress", box_value(probeAddress));
                }
                const auto configuration = SerializeProfile(settings.options, settings.credentialReference);
                if (target)
                {
                    const auto existing = ParseProfile(target.CustomConfiguration(), testName);
                    if (target.ConnectionStatus() != VpnManagementConnectionStatus::Disconnected ||
                        SerializeProfile(existing.options, existing.credentialReference) != configuration)
                        throw hresult_invalid_argument(L"Existing acceptance profile differs or is active; not overwritten");
                }
                else
                {
                    target = VpnPlugInProfile(); target.ProfileName(testName); target.VpnPluginPackageFamilyName(family);
                    target.ServerUris().Append(Uri(L"ikev2://" + settings.options.server));
                    target.CustomConfiguration(configuration); target.RequireVpnClientAppUI(true); target.RememberCredentials(false);
                    // Only the protected credential reference is reused. The PSK is never read here.
                    if (co_await agent.AddProfileFromObjectAsync(target) != VpnManagementErrorStatus::Ok)
                        throw hresult_error(E_FAIL, L"Windows rejected the separate MOBIKE acceptance profile");
                }
                values.Insert(L"MobikeProfileName", box_value(hstring(testName)));
                values.Insert(L"LastSelectedProfile", box_value(hstring(testName)));
                values.Insert(L"MobikeProfilePreparation", box_value(L"Ready"));
            }
            catch (hresult_error const& error) { values.Insert(L"MobikeProfilePreparation", box_value(error.message())); }
            catch (...) { values.Insert(L"MobikeProfilePreparation", box_value(L"Failed")); }
            values.Insert(L"MobikeProfilePreparedAt", box_value(clock::now()));
            SetBusy(false); PublishExistingProfiles();
        }
#endif

        void UpdateConditionalFields()
        {
            if (splitRoutes && routeMode.SelectedIndex() >= 0) splitRoutes.IsEnabled(Value(routeMode) == L"1");
            if (customDns && dnsMode.SelectedIndex() >= 0) customDns.IsEnabled(Value(dnsMode) == L"1");
        }

        void RenderStatus()
        {
            if (!status) return;
            status.Text(FormatUiText(std::wstring(T(statusKey.c_str())), std::wstring_view(statusArgument)));
            status.Opacity(statusError ? 1 : 0.8);
        }

        void SetStatus(wchar_t const* key, bool error = false, hstring const& argument = {})
        {
            statusKey = key; statusArgument = argument; statusError = error; RenderStatus();
        }

        void SetSystemError(hresult_error const& error)
        {
            if (error.code() == E_INVALIDARG) SetStatus(L"UI_InvalidProfile", true);
            else SetStatus(L"UI_SystemError", true, to_hstring(static_cast<int32_t>(error.code())));
        }

        void SetBusy(bool value)
        {
            busy = value; connections.IsEnabled(!value); add.IsEnabled(!value); refresh.IsEnabled(!value);
            create.IsEnabled(!value && !readOnly); defaults.IsEnabled(!value && !readOnly); tabs.IsEnabled(!value && !readOnly);
        }

        void ApplyOptions(ConnectionOptions const& o)
        {
            const bool previous = loading; loading = true;
            name.Text(o.name.empty() ? L"SwanBridge" : hstring(o.name)); server.Text(o.server); localId.Text(o.localId); remoteId.Text(o.remoteId);
            Select(localType,to_hstring(o.localIdType)); Select(remoteType,to_hstring(o.remoteIdType)); Select(ike,hstring(o.ikeProposal)); Select(esp,hstring(o.espProposal));
            Select(dpd,to_hstring(o.dpdDelay)); Select(keepAlive,to_hstring(o.keepAlive));
            Select(retransmitTimeout,to_hstring(o.retransmitTimeout)); Select(retransmitTries,to_hstring(o.retransmitTries));
            Select(keyingTries,to_hstring(o.keyingTries)); Select(childLifetime,to_hstring(o.childLifetime));
            Select(ikeRekey,to_hstring(o.ikeRekey)); Select(childRekeyPercent,to_hstring(o.childRekeyPercent)); Select(rekeyJitter,to_hstring(o.rekeyJitter));
            Select(connectTimeout,to_hstring(o.connectTimeout)); Select(fragmentation,to_hstring(o.fragmentation ? 1 : 0));
            Select(mobility,to_hstring(o.mobike ? 1 : 0));
            natPort.Text(to_hstring(o.natPort)); mtu.Text(to_hstring(o.mtu)); Select(routeMode,to_hstring(o.routeMode)); Select(dnsMode,to_hstring(o.dnsMode));
            excludeLocal.IsOn(o.excludeLocalSubnets); splitRoutes.Text(o.splitRoutes); customDns.Text(o.customDns);
            UpdateConditionalFields(); loading = previous;
        }

        ConnectionOptions ReadOptions()
        {
            ConnectionOptions o; o.name = name.Text(); o.server = server.Text(); o.localId = localId.Text(); o.remoteId = remoteId.Text();
            if (!ValidName(o.name)) throw UiError{L"UI_InvalidName"};
            if (!ValidServer(o.server)) throw UiError{L"UI_InvalidServer"};
            o.localIdType = ValueNumber(localType); o.remoteIdType = ValueNumber(remoteType);
            o.ikeProposal = Value(ike); o.espProposal = Value(esp); o.dpdDelay = ValueNumber(dpd); o.keepAlive = ValueNumber(keepAlive);
            o.retransmitTimeout = ValueNumber(retransmitTimeout); o.retransmitTries = ValueNumber(retransmitTries);
            o.keyingTries = ValueNumber(keyingTries); o.childLifetime = ValueNumber(childLifetime);
            o.ikeRekey = ValueNumber(ikeRekey); o.childRekeyPercent = ValueNumber(childRekeyPercent); o.rekeyJitter = ValueNumber(rekeyJitter);
            o.connectTimeout = ValueNumber(connectTimeout); o.fragmentation = ValueNumber(fragmentation) != 0;
            o.mobike = ValueNumber(mobility) != 0;
            const auto port = Number(natPort.Text(),L"UI_InvalidPort");
            if (!port || port > 65535) throw UiError{L"UI_InvalidPort"};
            o.natPort = static_cast<uint16_t>(port); o.mtu = Number(mtu.Text(),L"UI_InvalidMtu");
            if (o.mtu < 576 || o.mtu > 1400) throw UiError{L"UI_InvalidMtu"};
            o.routeMode = ValueNumber(routeMode); o.dnsMode = ValueNumber(dnsMode); o.excludeLocalSubnets = excludeLocal.IsOn();
            o.splitRoutes = splitRoutes.Text(); o.customDns = customDns.Text();
            std::uint32_t address;
            if ((o.localIdType == SB_ID_IPV4 ? !ParseIPv4(o.localId,address) : !ValidServer(o.localId)) ||
                (o.remoteIdType == SB_ID_IPV4 ? !ParseIPv4(o.remoteId,address) : !ValidServer(o.remoteId)))
                throw UiError{L"UI_InvalidIdentity"};
            if (!ValidOptions(o)) throw UiError{L"UI_InvalidOptions"};
            return o;
        }

        ProfileEditorState CaptureEditor() const
        {
            ProfileEditorState state;
            for (auto const& field : {name, server, localId, remoteId, natPort, mtu, splitRoutes, customDns})
                state.fields.emplace_back(field.Text());
            for (auto const& choice : {localType, remoteType, ike, esp, dpd, keepAlive, retransmitTimeout, retransmitTries,
                keyingTries, childLifetime, ikeRekey, childRekeyPercent, rekeyJitter, connectTimeout, fragmentation, mobility, routeMode, dnsMode})
                state.fields.emplace_back(Value(choice));
            state.excludeLocalSubnets = excludeLocal.IsOn();
            return state;
        }

        hstring State(VpnPlugInProfile const& profile)
        {
            switch (profile.ConnectionStatus())
            {
            case VpnManagementConnectionStatus::Connected: return T(L"UI_Connected");
            case VpnManagementConnectionStatus::Connecting: return T(L"UI_Connecting");
            case VpnManagementConnectionStatus::Disconnecting: return T(L"UI_Disconnecting");
            default: return T(L"UI_Disconnected");
            }
        }

        IAsyncOperation<bool> ConfirmDiscard()
        {
            if (!HasEditorChanges(CaptureEditor(), savedEditor, !psk.Password().empty())) co_return true;
            ContentDialog dialog; BindTransient(dialog, L"UI_UnsavedTitle", [](ContentDialog const& target, hstring const& value) { target.Title(box_value(value)); });
            BindTransient(dialog, L"UI_UnsavedBody", [](ContentDialog const& target, hstring const& value) { target.Content(box_value(value)); });
            dialog.RequestedTheme(viewRoot.ActualTheme());
            BindTransient(dialog, L"UI_DiscardChanges", [](ContentDialog const& target, hstring const& value) { target.PrimaryButtonText(value); });
            BindTransient(dialog, L"UI_KeepEditing", [](ContentDialog const& target, hstring const& value) { target.CloseButtonText(value); });
            co_return co_await dialog.ShowAsync() == ContentDialogResult::Primary;
        }

        void Load(int index)
        {
            loading = true; currentIndex = index; loadedXml = L""; credentialReference = L""; readOnly = false; unsupportedProfile = false; psk.Password(L""); name.IsReadOnly(index >= 0);
            if (index < 0)
            {
                ApplyOptions(ConnectionOptions{}); heading.Text(T(L"UI_NewConnection")); connectionState.Text(L"IKEv2 / PSK / strongSwan");
                passwordHelp.Text(T(L"UI_NewPskHelp"));
            }
            else
            {
                const auto profile = records.at(index).profile; heading.Text(profile.ProfileName()); connectionState.Text(State(profile)); loadedXml = profile.CustomConfiguration();
                try
                {
                    auto settings = ParseProfile(loadedXml,std::wstring(profile.ProfileName())); credentialReference = settings.credentialReference; ApplyOptions(settings.options);
                    readOnly = profile.ConnectionStatus() != VpnManagementConnectionStatus::Disconnected;
                    passwordHelp.Text(T(L"UI_KeepPskHelp"));
                    if (readOnly) connectionState.Text(State(profile) + T(L"UI_ReadOnlySuffix"));
                }
                catch (...)
                {
                    readOnly = true; unsupportedProfile = true; ApplyOptions(ConnectionOptions{}); name.Text(profile.ProfileName());
                    connectionState.Text(T(L"UI_UnsupportedProfile"));
                }
                ApplicationData::Current().LocalSettings().Values().Insert(L"LastSelectedProfile",box_value(profile.ProfileName()));
            }
            SetCommandLabel(create, index < 0 ? L"UI_CreateConnection" : L"UI_SaveChanges"); savedEditor = CaptureEditor(); loading = false; SetBusy(false);
        }

        fire_and_forget SelectProfile()
        {
            const auto lifetime = get_strong(); if (loading || busy || selecting) co_return;
            const auto target = connections.SelectedIndex(); if (target == currentIndex) co_return; selecting = true;
            try
            {
                if (co_await ConfirmDiscard())
                {
                    Load(target); SetStatus(L"UI_ProfileLoaded");
                    if (split.DisplayMode() == SplitViewDisplayMode::Overlay) split.IsPaneOpen(false);
                }
                else connections.SelectedIndex(currentIndex);
            }
            catch (UiError const& error) { connections.SelectedIndex(currentIndex); SetStatus(error.key, true, error.argument); }
            catch (hresult_error const& error) { connections.SelectedIndex(currentIndex); SetSystemError(error); }
            selecting = false;
        }

        fire_and_forget NewProfile()
        {
            const auto lifetime = get_strong(); if (busy || selecting) co_return; selecting = true;
            try
            {
                if (co_await ConfirmDiscard())
                {
                    loading = true; connections.SelectedIndex(-1); Load(-1); tabs.SelectedIndex(0); SetStatus(L"UI_NewProfileReady");
                    if (split.DisplayMode() == SplitViewDisplayMode::Overlay) split.IsPaneOpen(false);
                }
            }
            catch (UiError const& error) { SetStatus(error.key, true, error.argument); }
            catch (hresult_error const& error) { SetSystemError(error); }
            selecting = false;
        }

        void RestoreDefaults()
        {
            ConnectionOptions o; o.name = name.Text(); o.server = server.Text(); o.localId = localId.Text(); o.remoteId = remoteId.Text();
            o.localIdType = ValueNumber(localType); o.remoteIdType = ValueNumber(remoteType);
            ApplyOptions(o); SetStatus(L"UI_DefaultsRestored");
        }

        fire_and_forget PublishExistingProfiles(bool ask = false)
        {
            const auto lifetime = get_strong(); if (busy || selecting) co_return;
            SetBusy(true); uint32_t repaired = 0, deferred = 0, failed = 0;
            try
            {
                if (ask && !(co_await ConfirmDiscard())) { SetBusy(false); co_return; }
                auto preferred = currentIndex >= 0 && currentIndex < static_cast<int>(records.size()) ? records[currentIndex].profile.ProfileName() : hstring();
                const auto values = ApplicationData::Current().LocalSettings().Values();
                if (preferred.empty() && values.HasKey(L"LastSelectedProfile")) preferred = unbox_value<hstring>(values.Lookup(L"LastSelectedProfile"));
                VpnManagementAgent agent; const auto family = Package::Current().Id().FamilyName(); const auto profiles = co_await agent.GetProfilesAsync();
                for (const auto& existing : profiles)
                {
                    const auto profile = existing.try_as<VpnPlugInProfile>();
                    if (!profile || profile.VpnPluginPackageFamilyName() != family || profile.RequireVpnClientAppUI()) continue;
                    try { ParseProfile(profile.CustomConfiguration(),std::wstring(profile.ProfileName())); } catch (...) { continue; }
                    if (profile.ConnectionStatus() != VpnManagementConnectionStatus::Disconnected) { ++deferred; continue; }
                    try
                    {
                        profile.RequireVpnClientAppUI(true); const auto result = co_await agent.UpdateProfileFromObjectAsync(profile);
                        if (result == VpnManagementErrorStatus::Ok) ++repaired; else ++failed;
                    }
                    catch (...) { ++failed; }
                }
                const auto current = co_await agent.GetProfilesAsync(); loading = true; connections.Items().Clear(); records.clear(); currentIndex = -1; int selected = -1;
                for (const auto& item : current)
                {
                    const auto profile = item.try_as<VpnPlugInProfile>(); if (!profile || profile.VpnPluginPackageFamilyName() != family) continue;
                    if (profile.ProfileName() == preferred) selected = static_cast<int>(records.size()); records.push_back({profile});
                    StackPanel row; row.Spacing(4); row.Margin(Thickness{ 0,6,0,6 });
                    row.Children().Append(Text(profile.ProfileName(),14)); row.Children().Append(Text(State(profile),12,true));
                    ListViewItem listItem; listItem.HorizontalContentAlignment(HorizontalAlignment::Stretch); listItem.Content(row);
                    Windows::UI::Xaml::Automation::AutomationProperties::SetName(listItem,profile.ProfileName()); connections.Items().Append(listItem);
                }
                if (selected < 0 && !records.empty()) selected = 0; connections.SelectedIndex(selected); Load(selected);
                SetStatus(failed ? L"UI_VisibilityFailed" : deferred ? L"UI_VisibilityDeferred" :
                    L"UI_ProfilesRead", false, to_hstring(records.size()));
                values.Insert(L"ProfileVisibilityRepaired",box_value(repaired)); values.Insert(L"ProfileVisibilityDeferred",box_value(deferred));
                values.Insert(L"ProfileVisibilityFailed",box_value(failed)); values.Insert(L"ProfileVisibilityCheckedAt",box_value(clock::now()));
            }
            catch (UiError const& error) { loading = false; SetBusy(false); SetStatus(error.key, true, error.argument); }
            catch (hresult_error const& error) { loading = false; SetBusy(false); SetSystemError(error); }
            catch (...) { loading = false; SetBusy(false); SetStatus(L"UI_ReadFailed",true); }
        }

        fire_and_forget CreateProfile()
        {
            const auto lifetime = get_strong(); if (busy || readOnly) co_return; SetBusy(true);
            StorageFile credentialFile{ nullptr }; Windows::Storage::Streams::IBuffer plaintext{ nullptr }; bool profileAdded = false;
            try
            {
                const auto options = ReadOptions(); const bool updating = currentIndex >= 0; VpnManagementAgent agent;
                const auto profiles = co_await agent.GetProfilesAsync(); VpnPlugInProfile profile{ nullptr };
                for (const auto& existing : profiles)
                {
                    if (existing.ProfileName() != options.name) continue;
                    if (!updating) throw UiError{L"UI_NameExists"};
                    profile = existing.try_as<VpnPlugInProfile>();
                }
                hstring reference = credentialReference;
                if (updating)
                {
                    if (!profile || profile.VpnPluginPackageFamilyName() != Package::Current().Id().FamilyName() || profile.CustomConfiguration() != loadedXml)
                        throw UiError{L"UI_ProfileChanged"};
                    if (profile.ConnectionStatus() != VpnManagementConnectionStatus::Disconnected)
                        throw UiError{L"UI_ProfileActive"};
                }
                else { profile = VpnPlugInProfile(); profile.ProfileName(options.name); }
                if (!psk.Password().empty())
                {
                    plaintext = Windows::Security::Cryptography::CryptographicBuffer::ConvertStringToBinary(psk.Password(),Windows::Security::Cryptography::BinaryStringEncoding::Utf8);
                    if (!plaintext.Length() || plaintext.Length() > 1024) throw UiError{L"UI_InvalidPskLength"};
                    guid id; check_hresult(CoCreateGuid(reinterpret_cast<GUID*>(&id))); reference = to_hstring(id);
                    Windows::Security::Cryptography::DataProtection::DataProtectionProvider protector(L"LOCAL=user");
                    const auto encrypted = co_await protector.ProtectAsync(plaintext); SecureZeroMemory(plaintext.data(),plaintext.Length()); plaintext = nullptr;
                    const auto folder = co_await ApplicationData::Current().LocalFolder().CreateFolderAsync(L"Credentials",CreationCollisionOption::OpenIfExists);
                    credentialFile = co_await folder.CreateFileAsync(reference + L".bin",CreationCollisionOption::FailIfExists); co_await FileIO::WriteBufferAsync(credentialFile,encrypted);
                }
                else if (!updating) throw UiError{L"UI_PskRequired"};
                profile.VpnPluginPackageFamilyName(Package::Current().Id().FamilyName());
                profile.ServerUris().Clear(); profile.ServerUris().Append(Uri(L"ikev2://" + options.server));
                profile.CustomConfiguration(SerializeProfile(options,reference)); profile.RequireVpnClientAppUI(true); profile.RememberCredentials(false);
                const auto result = updating ? co_await agent.UpdateProfileFromObjectAsync(profile) : co_await agent.AddProfileFromObjectAsync(profile);
                if (result != VpnManagementErrorStatus::Ok) throw UiError{L"UI_WindowsRejected", to_hstring(static_cast<int>(result))};
                profileAdded = true; psk.Password(L""); savedEditor = CaptureEditor(); ApplicationData::Current().LocalSettings().Values().Insert(L"LastSelectedProfile",box_value(hstring(options.name)));
                SetBusy(false); PublishExistingProfiles();
            }
            catch (UiError const& error) { SetStatus(error.key, true, error.argument); }
            catch (hresult_error const& error) { SetSystemError(error); }
            catch (...) { SetStatus(L"UI_SaveFailed",true); }
            if (plaintext) SecureZeroMemory(plaintext.data(),plaintext.Length());
            if (credentialFile && !profileAdded) { try { co_await credentialFile.DeleteAsync(StorageDeleteOption::PermanentDelete); } catch (...) {} }
            if (!profileAdded) SetBusy(false);
        }
    };
}

int __stdcall wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    init_apartment(apartment_type::multi_threaded);
    Application::Start([](auto&&) { make<swanbridge::App>(); });
}
