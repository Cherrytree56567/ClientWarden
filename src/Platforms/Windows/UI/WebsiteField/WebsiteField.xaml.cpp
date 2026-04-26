#include "pch.h"
#include "WebsiteField.xaml.h"
#if __has_include("WebsiteField.g.cpp")
#include "WebsiteField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring WebsiteField::Title() {
        return FieldName().Text();
    }

    void WebsiteField::Title(winrt::hstring const& value) {
        FieldName().Text(value);
    }

    Microsoft::UI::Xaml::Controls::UIElementCollection WebsiteField::Value() {
        return FieldValue().Children();
    }

    void WebsiteField::Value(Microsoft::UI::Xaml::Controls::UIElementCollection value) {
        for (auto const& child : value) {
            FieldValue().Children().Append(child);
        }
    }
}
