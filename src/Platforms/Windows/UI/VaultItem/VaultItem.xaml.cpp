#include "pch.h"
#include "VaultItem.xaml.h"
#if __has_include("VaultItem.g.cpp")
#include "VaultItem.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure, 
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::Microsoft::UI::Xaml::Media::ImageSource VaultItem::Logo() {
        return LoginIcon().Source();
    }

    void VaultItem::Logo(winrt::Microsoft::UI::Xaml::Media::ImageSource const& value) {
        LoginIcon().Source(value);
    }

    winrt::hstring VaultItem::Title() {
        return LoginName().Text();
    }

    void VaultItem::Title(winrt::hstring const& value) {
        LoginName().Text(value);
    }

    winrt::hstring VaultItem::Detail() {
        return LoginDetail().Text();
    }

    void VaultItem::Detail(winrt::hstring const& value) {
        LoginDetail().Text(value);
    }

    winrt::event_token VaultItem::Click(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_clickEvent.add(handler);
    }

    void VaultItem::Click(winrt::event_token const& token) {
        m_clickEvent.remove(token);
    }

    winrt::hstring VaultItem::itemID() {
        return idItem;
    }

    void VaultItem::itemID(winrt::hstring const& value) {
        idItem = value;
    }

    void VaultItem::Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_clickEvent(*this, e);
    }
}
