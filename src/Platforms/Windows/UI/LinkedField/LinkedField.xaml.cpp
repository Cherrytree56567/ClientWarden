#include "pch.h"
#include "LinkedField.xaml.h"
#if __has_include("LinkedField.g.cpp")
#include "LinkedField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring LinkedField::Title() {
        return FieldName().Text();
    }

    void LinkedField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring LinkedField::Value() {
        return FieldValue().Text();
    }

    void LinkedField::Value(winrt::hstring value) {
        FieldValue().Text(value);
    }
}
