#pragma once

#include "Vault.g.h"

namespace winrt::WindowsUI::implementation
{
    struct Vault : VaultT<Vault>
    {
        Vault()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        int32_t MyProperty();
        void MyProperty(int32_t value);
        void NavigationView_Loaded(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct Vault : VaultT<Vault, implementation::Vault>
    {
    };
}
