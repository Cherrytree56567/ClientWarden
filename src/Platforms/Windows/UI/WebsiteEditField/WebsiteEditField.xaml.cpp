#include "pch.h"
#include "WebsiteEditField.xaml.h"
#if __has_include("WebsiteEditField.g.cpp")
#include "WebsiteEditField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring WebsiteEditField::Title() {
        return FieldName().Text();
    }

    void WebsiteEditField::Title(winrt::hstring const& value) {
        FieldName().Text(value);
    }

    void WebsiteEditField::AddField(winrt::hstring text) {
        auto field = winrt::Microsoft::UI::Xaml::Controls::TextBox();
        field.Text(text);
        field.FontSize(14);
        field.Margin(winrt::Microsoft::UI::Xaml::ThicknessHelper::FromLengths(-10, 2, -10, 0));
        field.CornerRadius(winrt::Microsoft::UI::Xaml::CornerRadiusHelper::FromRadii(0, 0, 0, 0));
        field.BorderThickness(winrt::Microsoft::UI::Xaml::ThicknessHelper::FromUniformLength(0));
        field.Background(nullptr);
        field.TextChanged([this](auto sender, auto) {
            auto textBox = sender.as<winrt::Microsoft::UI::Xaml::Controls::TextBox>();
            if (textBox.Text().empty()) {
                auto parent = textBox.Parent().as<winrt::Microsoft::UI::Xaml::Controls::Panel>();
                uint32_t index;
                parent.Children().IndexOf(textBox, index);
                parent.Children().RemoveAt(index);
            }
        });

        FieldValues().Children().Append(field);
    }

    void WebsiteEditField::AddButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        AddField(L"");
    }

    Windows::Foundation::Collections::IVector<winrt::hstring> WebsiteEditField::GetFields() {
        auto strings = winrt::single_threaded_vector<winrt::hstring>();

        for (auto child : FieldValues().Children()) {
            if (auto field = child.try_as<winrt::Microsoft::UI::Xaml::Controls::TextBox>()) {
                strings.Append(field.Text());
            }
        }

        return strings;
    }
}
