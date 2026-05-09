#include "pch.h"
#include "PasswordEditField.xaml.h"
#if __has_include("PasswordEditField.g.cpp")
#include "PasswordEditField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring PasswordEditField::Title() {
        return FieldName().Text();
    }

    void PasswordEditField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring PasswordEditField::Value() {
        return FieldValue().Password();
    }

    void PasswordEditField::Value(winrt::hstring value) {
        FieldValue().Password(value);
        FieldValue().PasswordRevealMode(winrt::Microsoft::UI::Xaml::Controls::PasswordRevealMode::Visible);
    }
}