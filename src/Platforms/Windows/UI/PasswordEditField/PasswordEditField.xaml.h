#pragma once

#include "PasswordEditField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct PasswordEditField : PasswordEditFieldT<PasswordEditField>
    {
        PasswordEditField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring value);

        winrt::hstring Value();
        void Value(winrt::hstring value);

        void PassGen_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Input::TappedRoutedEventArgs const& e);
        void PassGenList_Changed(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args);

        void DisablePasswordGen();
    private:
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_clipboardEvent;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct PasswordEditField : PasswordEditFieldT<PasswordEditField, implementation::PasswordEditField>
    {
    };
}
