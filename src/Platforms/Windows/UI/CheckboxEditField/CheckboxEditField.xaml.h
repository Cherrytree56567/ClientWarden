#pragma once

#include "CheckboxEditField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct CheckboxEditField : CheckboxEditFieldT<CheckboxEditField>
    {
        CheckboxEditField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring const& value);

        bool Value();
        void Value(bool value);

        winrt::event_token DeleteField(Microsoft::UI::Xaml::RoutedEventHandler const& handler);
        void DeleteField(winrt::event_token const& token);
        
        void DeleteButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    private:
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_DeleteFieldEvent;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct CheckboxEditField : CheckboxEditFieldT<CheckboxEditField, implementation::CheckboxEditField>
    {
    };
}
