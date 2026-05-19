#include "pch.h"
#include "AttachmentField.xaml.h"
#if __has_include("AttachmentField.g.cpp")
#include "AttachmentField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring AttachmentField::Title() {
        return FieldName().Text();
    }

    void AttachmentField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring AttachmentField::Value() {
        return val;
    }

    void AttachmentField::Value(winrt::hstring value) {
        val = value;
    }

    winrt::event_token AttachmentField::Download(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_downloadEvent.add(handler);
    }

    void AttachmentField::Download(winrt::event_token const& token) {
        m_downloadEvent.remove(token);
    }

    void AttachmentField::Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_downloadEvent(*this, e);
    }
}