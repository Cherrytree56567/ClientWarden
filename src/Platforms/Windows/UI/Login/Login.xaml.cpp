#include "pch.h"
#include "Login.xaml.h"
#if __has_include("Login.g.cpp")
#include "Login.g.cpp"
#endif
#include "MainWindow/MainWindow.xaml.h"

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    void Login::LoginButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        FieldError().Text(L"");

        std::string email = winrt::to_string(FieldEmail().Text());
        std::string password = winrt::to_string(FieldPassword().Password());

        ClientWarden::Vault::AuthState result = vault.Login(email, password);

        if (result == ClientWarden::Vault::AuthState::NeedsTOTP) {
            std::string otp;
            std::cout << "OTP: ";
            std::cin >> otp;
            vault.submitTOTP(otp);
        } else if (result == ClientWarden::Vault::AuthState::NeedsEmailVerification) {
            std::string newDevice;
            std::cout << "New Device Code: ";
            std::cin >> newDevice;
            vault.submitDeviceVerify(newDevice);
        } else if (result != ClientWarden::Vault::AuthState::Authenticated) {
            FieldError().Text(L"Wrong email or password!");
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