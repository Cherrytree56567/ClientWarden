#pragma once

#include "HiddenEditField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct HiddenEditField : HiddenEditFieldT<HiddenEditField>
    {
        HiddenEditField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring const& value);

        winrt::hstring Value();
        void Value(winrt::hstring const& value);

        winrt::event_token DeleteField(Microsoft::UI::Xaml::RoutedEventHandler const& handler);
        void DeleteField(winrt::event_token const& token);
        
        void DeleteButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    private:
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_DeleteFieldEvent;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct HiddenEditField : HiddenEditFieldT<HiddenEditField, implementation::HiddenEditField>
    {
    };
}
