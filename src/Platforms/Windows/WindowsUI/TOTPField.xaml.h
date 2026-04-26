#pragma once

#include "TOTPField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct TOTPField : TOTPFieldT<TOTPField>
    {
        TOTPField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        int32_t Time();
        void Time(int32_t value);

        winrt::hstring Title();
        void Title(winrt::hstring value);

        winrt::hstring Value();
        void Value(winrt::hstring value);

        winrt::event_token Clipboard(Microsoft::UI::Xaml::RoutedEventHandler const& handler);
        void Clipboard(winrt::event_token const& token);

        void Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    private:
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_clipboardEvent;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct TOTPField : TOTPFieldT<TOTPField, implementation::TOTPField>
    {
    };
}
