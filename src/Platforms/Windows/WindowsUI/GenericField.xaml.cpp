#include "pch.h"
#include "GenericField.xaml.h"
#if __has_include("GenericField.g.cpp")
#include "GenericField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring GenericField::Title() {
        return FieldName().Text();
    }

    void GenericField::Title(winrt::hstring const& value) {
        FieldName().Text(value);
    }

    winrt::hstring GenericField::Value() {
        return FieldValue().Text();
    }

    void GenericField::Value(winrt::hstring const& value) {
        FieldValue().Text(value);
    }

    winrt::event_token GenericField::Clipboard(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_clipboardEvent.add(handler);
    }

    void GenericField::Clipboard(winrt::event_token const& token) {
        m_clipboardEvent.remove(token);
    }

    void GenericField::Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_clipboardEvent(*this, e);
    }
}
