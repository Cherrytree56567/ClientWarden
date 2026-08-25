#pragma once
#include "MainWindow.g.h"

namespace winrt::WindowsUI::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow();

        void Grid_Loaded(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e);
        void OnWindowClosing(winrt::Microsoft::UI::Windowing::AppWindow const&, winrt::Microsoft::UI::Windowing::AppWindowClosingEventArgs const& args);
        
        static MainWindow* mwstatic;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
