#include "pch.h"
#include "CheckboxField.xaml.h"
#if __has_include("CheckboxField.g.cpp")
#include "CheckboxField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring CheckboxField::Title() {
        return winrt::unbox_value<winrt::hstring>(Field().Content());
    }

    void CheckboxField::Title(winrt::hstring const& value) {
        Field().Content(winrt::box_value(value));
    }

    bool CheckboxField::Value() {
        return Field().IsChecked().GetBoolean();
    }

    void CheckboxField::Value(bool value) {
        Field().IsChecked(value);
    }
}
