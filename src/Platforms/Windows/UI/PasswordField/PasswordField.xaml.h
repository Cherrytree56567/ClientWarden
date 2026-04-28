#pragma once

#include "PasswordField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct PasswordField : PasswordFieldT<PasswordField>
    {
        PasswordField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring value);

        winrt::hstring Value();
        void Value(winrt::hstring value);

        winrt::event_token Clipboard(Microsoft::UI::Xaml::RoutedEventHandler const& handler);
        void Clipboard(winrt::event_token const& token);

        winrt::event_token ShowHide(Microsoft::UI::Xaml::RoutedEventHandler const& handler);
        void ShowHide(winrt::event_token const& token);

        winrt::Microsoft::UI::Xaml::Controls::BitmapIcon GetShowHideImage();

        void Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
        void Button_Click_1(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    private:
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_clipboardEvent;
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_showhideEvent;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct PasswordField : PasswordFieldT<PasswordField, implementation::PasswordField>
    {
    };
}
