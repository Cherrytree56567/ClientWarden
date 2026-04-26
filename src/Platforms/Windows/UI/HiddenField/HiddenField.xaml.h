#pragma once

#include "HiddenField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct HiddenField : HiddenFieldT<HiddenField>
    {
        HiddenField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring const& value);

        winrt::hstring Value();
        void Value(winrt::hstring const& value);

        winrt::event_token ShowHide(Microsoft::UI::Xaml::RoutedEventHandler const& handler);
        void ShowHide(winrt::event_token const& token);

        void FieldButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    private:
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_showhideEvent;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct HiddenField : HiddenFieldT<HiddenField, implementation::HiddenField>
    {
    };
}
