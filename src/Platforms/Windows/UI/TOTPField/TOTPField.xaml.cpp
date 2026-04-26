#include "pch.h"
#include "TOTPField.xaml.h"
#if __has_include("TOTPField.g.cpp")
#include "TOTPField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    int32_t TOTPField::Time()
    {
        return FieldRing().Value();
    }

    void TOTPField::Time(int32_t value)
    {
        FieldRing().Value(value);

        std::wstring str = std::to_wstring(value);
        FieldRingText().Text(winrt::hstring{ str });
    }

    winrt::hstring TOTPField::Title() {
        return FieldName().Text();
    }

    void TOTPField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring TOTPField::Value() {
        return FieldValue().Text();
    }

    void TOTPField::Value(winrt::hstring value) {
        FieldValue().Text(value);
    }

    winrt::event_token TOTPField::Clipboard(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_clipboardEvent.add(handler);
    }

    void TOTPField::Clipboard(winrt::event_token const& token) {
        m_clipboardEvent.remove(token);
    }

    void TOTPField::Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_clipboardEvent(*this, e);
    }
}
