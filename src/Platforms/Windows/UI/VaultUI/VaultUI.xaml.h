#pragma once

#include "VaultUI.g.h"

namespace winrt::WindowsUI::implementation
{
    struct VaultUI : VaultUIT<VaultUI>
    {
        VaultUI()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        void AddItem(winrt::hstring itemID);
        void RemoveItem(winrt::hstring itemID);

        void NavigationView_Loaded(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
        void VaultItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct VaultUI : VaultUIT<VaultUI, implementation::VaultUI>
    {
    };
}
