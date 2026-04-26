#pragma once
#include <stdexcept>
#include "Vault/Vault.h"
#include "Unlock.g.h"

namespace winrt::WindowsUI::implementation
{
    struct Unlock : UnlockT<Unlock>
    {
        Unlock()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        void UnlockButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct Unlock : UnlockT<Unlock, implementation::Unlock>
    {
    };
}
