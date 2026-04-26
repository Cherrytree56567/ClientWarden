#pragma once
#include "MainWindow.g.h"
#include "Vault/Vault.h"
#include "VaultUI/VaultUI.xaml.h"
#include "Login/Login.xaml.h"
#include "Unlock/Unlock.xaml.h"

namespace winrt::WindowsUI::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow();

        void Grid_Loaded(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
        void OnWindowClosing(winrt::Microsoft::UI::Windowing::AppWindow const&, winrt::Microsoft::UI::Windowing::AppWindowClosingEventArgs const& args);
        
        void postAuth();
        
        static MainWindow* mwstatic;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
