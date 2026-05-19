#include "pch.h"
#include "AttachmentEditField.xaml.h"
#if __has_include("AttachmentEditField.g.cpp")
#include "AttachmentEditField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring AttachmentEditField::Title() {
        return FieldName().Text();
    }

    void AttachmentEditField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring AttachmentEditField::Value() {
        return val;
    }

    void AttachmentEditField::Value(winrt::hstring value) {
        val = value;
    }

    winrt::event_token AttachmentEditField::Bin(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_binEvent.add(handler);
    }

    void AttachmentEditField::Bin(winrt::event_token const& token) {
        m_binEvent.remove(token);
    }

    void AttachmentEditField::Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_binEvent(*this, e);
    }
}