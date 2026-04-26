#pragma once

#include "VaultItem.g.h"

namespace winrt::WindowsUI::implementation
{
    struct VaultItem : VaultItemT<VaultItem>
    {
        VaultItem()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::Microsoft::UI::Xaml::Media::ImageSource Logo();
        void Logo(winrt::Microsoft::UI::Xaml::Media::ImageSource const& value);

        winrt::hstring Title();
        void Title(winrt::hstring const& value);

        winrt::hstring Detail();
        void Detail(winrt::hstring const& value);

        winrt::event_token Click(Microsoft::UI::Xaml::RoutedEventHandler const& handler);
        void Click(winrt::event_token const& token);

        winrt::hstring itemID();
        void itemID(winrt::hstring const& value);

        void Button_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    private:
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_clickEvent;
        winrt::hstring idItem;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct VaultItem : VaultItemT<VaultItem, implementation::VaultItem>
    {
    };
}
