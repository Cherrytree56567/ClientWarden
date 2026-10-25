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

    void MainWindow::Grid_Loaded(IInspectable const&, RoutedEventArgs const&) {

    }

    void MainWindow::OnWindowClosing(winrt::Microsoft::UI::Windowing::AppWindow const&, winrt::Microsoft::UI::Windowing::AppWindowClosingEventArgs const& args) {

    }
}
