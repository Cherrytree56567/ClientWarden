#include "pch.h"
#include "DeviceVerify.xaml.h"
#if __has_include("DeviceVerify.g.cpp")
#include "DeviceVerify.g.cpp"
#endif
#include "MainWindow/MainWindow.xaml.h"
#include <Microsoft.UI.Xaml.Window.h>

#include <windows.h>

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    void DeviceVerify::SubmitButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        FieldError().Text(L"");

        std::string otp = winrt::to_string(FieldCode().Text());

        ClientWarden::Vault::AuthState result = vault.submitDeviceVerify(otp);

        if (result != ClientWarden::Vault::AuthState::Authenticated) {
            FieldError().Text(L"Wrong code!");
            return;
        }

        if (vault.postLogin() != ClientWarden::Vault::NetworkState::Success) {
            spdlog::info("Failed to login");
            FieldError().Text(L"Wrong email or password!");
        }

        auto mainWindow = winrt::WindowsUI::implementation::MainWindow::mwstatic;
        mainWindow->postAuth();
    }
}