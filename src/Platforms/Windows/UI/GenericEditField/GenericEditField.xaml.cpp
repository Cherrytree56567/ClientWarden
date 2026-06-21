#include "pch.h"
#include "GenericEditField.xaml.h"
#if __has_include("GenericEditField.g.cpp")
#include "GenericEditField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring GenericEditField::Title() {
        return FieldName().Text();
    }

    void GenericEditField::Title(winrt::hstring const& value) {
        FieldName().Text(value);
    }

    winrt::hstring GenericEditField::Value() {
        return FieldValue().Text();
    }

    void GenericEditField::Value(winrt::hstring const& value) {
        FieldValue().Text(value);
    }

    bool GenericEditField::Wrap() {
        if (FieldValue().TextWrapping() == Microsoft::UI::Xaml::TextWrapping::Wrap) {
            return true;
        } else {
            return false;
        }
    }

    void GenericEditField::Wrap(bool const& value) {
        if (value) {
            FieldValue().TextWrapping(Microsoft::UI::Xaml::TextWrapping::Wrap);
            FieldValue().AcceptsReturn(true);
        } else {
            FieldValue().TextWrapping(Microsoft::UI::Xaml::TextWrapping::NoWrap);
            FieldValue().AcceptsReturn(false);
        }
    }
}
