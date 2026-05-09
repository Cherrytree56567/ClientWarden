#include "pch.h"
#include "LinkedEditField.xaml.h"
#if __has_include("LinkedEditField.g.cpp")
#include "LinkedEditField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring LinkedEditField::Title() {
        return FieldName().Text();
    }

    void LinkedEditField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring LinkedEditField::Value() {
        auto selected = FieldValue().SelectedItem();
        if (selected == nullptr) return L"";
        if (auto item = selected.try_as<winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem>()) {
            return winrt::unbox_value<winrt::hstring>(item.Content());
        }
        return L"";
    }

    void LinkedEditField::Value(winrt::hstring value) {
        for (uint32_t i = 0; i < FieldValue().Items().Size(); i++) {
            auto item = FieldValue().Items().GetAt(i).try_as<winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem>();
            if (item && winrt::unbox_value<winrt::hstring>(item.Content()) == value) {
                FieldValue().SelectedIndex(i);
                return;
            }
        }
    }

    void LinkedEditField::AddOption(winrt::hstring value) {
        auto item = winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem();
        item.Content(winrt::box_value(value));
        FieldValue().Items().Append(item);
    }

    winrt::event_token LinkedEditField::DeleteField(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_DeleteFieldEvent.add(handler);
    }

    void LinkedEditField::DeleteField(winrt::event_token const& token) {
        m_DeleteFieldEvent.remove(token);
    }
    
    void LinkedEditField::DeleteButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_DeleteFieldEvent(*this, e);
    }
}
