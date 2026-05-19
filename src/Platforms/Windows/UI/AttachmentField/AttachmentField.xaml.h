#pragma once

#include "AttachmentField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct AttachmentField : AttachmentFieldT<AttachmentField>
    {
        AttachmentField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring value);

        winrt::hstring Value();
        void Value(winrt::hstring value);

        winrt::event_token Download(Microsoft::UI::Xaml::RoutedEventHandler const& handler);
        void Download(winrt::event_token const& token);
        
        void Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    private:
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_downloadEvent;
        winrt::hstring val;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct AttachmentField : AttachmentFieldT<AttachmentField, implementation::AttachmentField>
    {
    };
}
