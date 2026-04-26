#include "pch.h"
#include "TextField.xaml.h"
#if __has_include("TextField.g.cpp")
#include "TextField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring TextField::Title() {
        return FieldName().Text();
    }

    void TextField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring TextField::Value() {
        return FieldValue().Text();
    }

    void TextField::Value(winrt::hstring value) {
        FieldValue().Text(value);
    }
}
