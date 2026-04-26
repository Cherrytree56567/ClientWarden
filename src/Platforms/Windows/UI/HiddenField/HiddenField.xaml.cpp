#include "pch.h"
#include "HiddenField.xaml.h"
#if __has_include("HiddenField.g.cpp")
#include "HiddenField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring HiddenField::Title() {
        return FieldName().Text();
    }

    void HiddenField::Title(winrt::hstring const& value) {
        FieldName().Text(value);
    }

    winrt::hstring HiddenField::Value() {
        return FieldValue().Text();
    }

    void HiddenField::Value(winrt::hstring const& value) {
        FieldValue().Text(value);
    }

    winrt::event_token HiddenField::ShowHide(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_showhideEvent.add(handler);
    }

    void HiddenField::ShowHide(winrt::event_token const& token) {
        m_showhideEvent.remove(token);
    }

    void HiddenField::FieldButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_showhideEvent(*this, e);
    }
}
