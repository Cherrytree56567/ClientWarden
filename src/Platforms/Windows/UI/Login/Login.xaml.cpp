#include "pch.h"
#include "Login.xaml.h"
#if __has_include("Login.g.cpp")
#include "Login.g.cpp"
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
    void Login::LoginButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string vaultUri;
        std::string mainUri;
        std::string apiUri;
        std::string iconUri;

        auto selected = UriMode().SelectedItem().as<winrt::Microsoft::UI::Xaml::Controls::ListViewItem>();

        std::string value = winrt::to_string(selected.Content().as<winrt::hstring>());

        if (value == "Bitwarden") {
            vaultUri = "https://vault.bitwarden.com";
            mainUri = "https://bitwarden.com";
            apiUri = "https://api.bitwarden.com";
            iconUri = "https://icons.bitwarden.net";
        } else if (value == "Self-Hosted") {
            vaultUri = winrt::to_string(VaultUri().Text());
            mainUri = winrt::to_string(MainUri().Text());
            apiUri = winrt::to_string(ApiUri().Text());
            iconUri = winrt::to_string(IconUri().Text());
        }

        vault.SetUris(vaultUri, mainUri, apiUri, iconUri);

        FieldError().Text(L"");

        std::string email = winrt::to_string(FieldEmail().Text());
        std::string password = winrt::to_string(FieldPassword().Password());

        ClientWarden::Vault::AuthState result = vault.Login(email, password);

        auto mainWindow = winrt::WindowsUI::implementation::MainWindow::mwstatic;

        if (result == ClientWarden::Vault::AuthState::NeedsTOTP) {
            FieldError().Text(L"TOTP Not Supported");
            return;
        } else if (result == ClientWarden::Vault::AuthState::NeedsEmailVerification) {
            mainWindow->deviceVerifySwitch();
            return;
        } else if (result != ClientWarden::Vault::AuthState::Authenticated) {
            FieldError().Text(L"Wrong email or password!");
            return;
        }

        if (vault.postLogin() != ClientWarden::Vault::NetworkState::Success) {
            spdlog::info("Failed to login");
            FieldError().Text(L"Wrong email or password!");
        }

        mainWindow->postAuth();
    }

    void Login::UriMode_SelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& e) {
        auto list = sender.as<winrt::Microsoft::UI::Xaml::Controls::ListView>();
        auto selected = list.SelectedItem().as<winrt::Microsoft::UI::Xaml::Controls::ListViewItem>();

        if (!selected) return;
        if (!VaultUri()) return;
        
        std::string value = winrt::to_string(selected.Content().as<winrt::hstring>());

        if (value == "Bitwarden") {
            VaultUriText().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            VaultUri().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            MainUriText().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            MainUri().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            ApiUriText().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            ApiUri().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            IconUriText().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            IconUri().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
        } else if (value == "Self-Hosted") {
            VaultUriText().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            VaultUri().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            MainUriText().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            MainUri().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            ApiUriText().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            ApiUri().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            IconUriText().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            IconUri().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
        }
    }
}