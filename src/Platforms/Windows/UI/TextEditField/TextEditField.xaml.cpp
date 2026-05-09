#include "pch.h"
#include "TextEditField.xaml.h"
#if __has_include("TextEditField.g.cpp")
#include "TextEditField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring TextEditField::Title() {
        return FieldName().Text();
    }

    void TextEditField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring TextEditField::Value() {
        return FieldValue().Text();
    }

    void TextEditField::Value(winrt::hstring value) {
        FieldValue().Text(value);
    }

    winrt::event_token TextEditField::DeleteField(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_DeleteFieldEvent.add(handler);
    }

    void TextEditField::DeleteField(winrt::event_token const& token) {
        m_DeleteFieldEvent.remove(token);
    }
    
    void TextEditField::DeleteButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_DeleteFieldEvent(*this, e);
    }
}
