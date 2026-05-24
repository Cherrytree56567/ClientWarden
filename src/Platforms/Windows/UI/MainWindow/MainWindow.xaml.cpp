#include "pch.h"
#include "MainWindow.xaml.h"
#if __has_include("MainWindow.g.cpp")
#include "MainWindow.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    MainWindow* MainWindow::mwstatic = nullptr;

    MainWindow::MainWindow() {
        mwstatic = this;
        ExtendsContentIntoTitleBar(true);

        winrt::Microsoft::UI::Windowing::AppWindow appWindow = this->AppWindow();
        //appWindow.Resize({ 400, 560 });
        appWindow.Resize({ 1000, 620 });
        appWindow.Closing({ this, &MainWindow::OnWindowClosing });

        winrt::Microsoft::UI::Windowing::OverlappedPresenter presenter = appWindow.Presenter().as<winrt::Microsoft::UI::Windowing::OverlappedPresenter>();
        presenter.IsResizable(true);
    }

    void MainWindow::postAuth() {
        winrt::hstring vaulttypeName{ winrt::name_of<WindowsUI::VaultUI>() };
        winrt::Windows::UI::Xaml::Interop::TypeName vaultType{vaulttypeName, winrt::Windows::UI::Xaml::Interop::TypeKind::Metadata};

        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        MainFrame().Navigate(vaultType);

        vault.startRefreshThread();
        vault.startWSSLoop();
        vault.Sync();
    }

    void MainWindow::deviceVerifySwitch() {
        winrt::hstring devVerifytypeName{ winrt::name_of<WindowsUI::DeviceVerify>() };
        winrt::Windows::UI::Xaml::Interop::TypeName devVerifyType{devVerifytypeName, winrt::Windows::UI::Xaml::Interop::TypeKind::Metadata};

        MainFrame().Navigate(devVerifyType);
    }

    void MainWindow::OnWindowClosing(winrt::Microsoft::UI::Windowing::AppWindow const&, winrt::Microsoft::UI::Windowing::AppWindowClosingEventArgs const& args) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        auto frame = MainFrame().CurrentSourcePageType();
        if (auto vaultUI = MainFrame().Content().try_as<winrt::WindowsUI::VaultUI>()) {
            vaultUI.StopTOTPThread();
        }

        vault.Lock();
    }

    void MainWindow::Grid_Loaded(IInspectable const&, RoutedEventArgs const&) {
        winrt::hstring logintypeName{ winrt::name_of<WindowsUI::Login>() };
        winrt::Windows::UI::Xaml::Interop::TypeName loginType{logintypeName, winrt::Windows::UI::Xaml::Interop::TypeKind::Metadata};
        winrt::hstring unlocktypeName{ winrt::name_of<WindowsUI::Unlock>() };
        winrt::Windows::UI::Xaml::Interop::TypeName unlockType{unlocktypeName, winrt::Windows::UI::Xaml::Interop::TypeKind::Metadata};

        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        MainFrame().Navigate(loginType);
        if (!vault.hasStoredSession()) {
            MainFrame().Navigate(loginType);
        } else {
            MainFrame().Navigate(unlockType);
        }
    }
}
