#include "pch.h"
#include "CheckboxEditField.xaml.h"
#if __has_include("CheckboxEditField.g.cpp")
#include "CheckboxEditField.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring CheckboxEditField::Title() {
        return FieldName().Text();
    }

    void CheckboxEditField::Title(winrt::hstring const& value) {
        FieldName().Text(value);
    }

    bool CheckboxEditField::Value() {
        return Field().IsChecked().GetBoolean();
    }

    void CheckboxEditField::Value(bool value) {
        Field().IsChecked(value);
    }

    winrt::event_token CheckboxEditField::DeleteField(Microsoft::UI::Xaml::RoutedEventHandler const& handler) {
        return m_DeleteFieldEvent.add(handler);
    }

    void CheckboxEditField::DeleteField(winrt::event_token const& token) {
        m_DeleteFieldEvent.remove(token);
    }
    
    void CheckboxEditField::DeleteButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        m_DeleteFieldEvent(*this, e);
    }
}
