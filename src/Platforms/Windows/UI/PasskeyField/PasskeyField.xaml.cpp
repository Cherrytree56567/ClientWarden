#include "pch.h"
#include "PasskeyField.xaml.h"
#if __has_include("PasskeyField.g.cpp")
#include "PasskeyField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring PasskeyField::Title() {
        return FieldName().Text();
    }

    void PasskeyField::Title(winrt::hstring const& value) {
        FieldName().Text(value);
    }

    winrt::hstring PasskeyField::Value() {
        return FieldValue().Text();
    }

    void PasskeyField::Value(winrt::hstring const& value) {
        FieldValue().Text(value);
    }
}
