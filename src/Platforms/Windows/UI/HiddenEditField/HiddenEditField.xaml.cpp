#include "pch.h"
#include "HiddenEditField.xaml.h"
#if __has_include("HiddenEditField.g.cpp")
#include "HiddenEditField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring HiddenEditField::Title() {
        return FieldName().Text();
    }

    void HiddenEditField::Title(winrt::hstring const& value) {
        FieldName().Text(value);
    }

    winrt::hstring HiddenEditField::Value() {
        return FieldValue().Password();
    }

    void HiddenEditField::Value(winrt::hstring const& value) {
        FieldValue().Password(value);
        FieldValue().PasswordRevealMode(winrt::Microsoft::UI::Xaml::Controls::PasswordRevealMode::Visible);
    }

    winrt::event_token HiddenEditField::DeleteField(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_DeleteFieldEvent.add(handler);
    }

    void HiddenEditField::DeleteField(winrt::event_token const& token) {
        m_DeleteFieldEvent.remove(token);
    }
    
    void HiddenEditField::DeleteButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_DeleteFieldEvent(*this, e);
    }
}
