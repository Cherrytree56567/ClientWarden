#include "pch.h"
#include "PasswordField.xaml.h"
#if __has_include("PasswordField.g.cpp")
#include "PasswordField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring PasswordField::Title() {
        return FieldName().Text();
    }

    void PasswordField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring PasswordField::Value() {
        return FieldValue().Text();
    }

    void PasswordField::Value(winrt::hstring value) {
        FieldValue().Text(value);
    }

    winrt::event_token PasswordField::Clipboard(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_clipboardEvent.add(handler);
    }

    void PasswordField::Clipboard(winrt::event_token const& token) {
        m_clipboardEvent.remove(token);
    }

    winrt::event_token PasswordField::ShowHide(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_showhideEvent.add(handler);
    }

    void PasswordField::ShowHide(winrt::event_token const& token) {
        m_showhideEvent.remove(token);
    }

    void PasswordField::Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_clipboardEvent(*this, e);
    }

    void PasswordField::Button_Click_1(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        if (ShowHideImage().UriSource().RawUri() == L"ms-appx:///Assets/ic_fluent_eye_show_24_regular.png") {
            ShowHideImage().UriSource(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_eye_hide_24_regular.png"));
        } else {
            ShowHideImage().UriSource(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_eye_show_24_regular.png"));
        }
        m_showhideEvent(*this, e);
    }

    winrt::Microsoft::UI::Xaml::Controls::BitmapIcon PasswordField::GetShowHideImage() {
        return ShowHideImage();
    }
}