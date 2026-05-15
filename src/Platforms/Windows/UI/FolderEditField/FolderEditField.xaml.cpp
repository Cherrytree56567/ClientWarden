#include "pch.h"
#include "FolderEditField.xaml.h"
#if __has_include("FolderEditField.g.cpp")
#include "FolderEditField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring FolderEditField::Title() {
        return FieldName().Text();
    }

    void FolderEditField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring FolderEditField::Value() {
        auto selected = FieldValue().SelectedItem();
        if (selected == nullptr) return L"";
        if (auto item = selected.try_as<winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem>()) {
            return winrt::unbox_value<winrt::hstring>(item.Content());
        }
        return L"";
    }

    void FolderEditField::Value(winrt::hstring value) {
        m_suppressSelectionChanged = true;
        for (uint32_t i = 0; i < FieldValue().Items().Size(); i++) {
            auto item = FieldValue().Items().GetAt(i).try_as<winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem>();
            auto newVal = winrt::unbox_value<winrt::hstring>(item.Content());
            if (item && newVal == value) {
                FieldValue().SelectedItem(item);
                m_suppressSelectionChanged = false;
                return;
            }
        }
        m_suppressSelectionChanged = false;
    }

    void FolderEditField::AddOption(winrt::hstring value) {
        auto item = winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem();
        item.Content(winrt::box_value(value));
        FieldValue().Items().Append(item);
    }

    winrt::Microsoft::UI::Xaml::Controls::ComboBox FolderEditField::GetComboBox() {
        return FieldValue();
    }
}
