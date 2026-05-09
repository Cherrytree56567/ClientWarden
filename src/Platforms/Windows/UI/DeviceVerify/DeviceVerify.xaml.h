#pragma once
#include "Vault/Vault.h"
#include "DeviceVerify.g.h"

namespace winrt::WindowsUI::implementation
{
    struct DeviceVerify : DeviceVerifyT<DeviceVerify>
    {
        DeviceVerify()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        void SubmitButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct DeviceVerify : DeviceVerifyT<DeviceVerify, implementation::DeviceVerify>
    {
    };
}
