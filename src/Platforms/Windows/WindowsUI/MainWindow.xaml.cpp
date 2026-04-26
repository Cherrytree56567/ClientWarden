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
    MainWindow::MainWindow() {
        ExtendsContentIntoTitleBar(true);

        winrt::Microsoft::UI::Windowing::AppWindow appWindow = this->AppWindow();
        //appWindow.Resize({ 400, 560 });
        appWindow.Resize({ 1000, 620 });

        winrt::Microsoft::UI::Windowing::OverlappedPresenter presenter = appWindow.Presenter().as<winrt::Microsoft::UI::Windowing::OverlappedPresenter>();
        presenter.IsResizable(true);
    }

    int32_t MainWindow::MyProperty()
    {
        throw hresult_not_implemented();
    }

    void MainWindow::MyProperty(int32_t /* value */)
    {
        throw hresult_not_implemented();
    }

    void MainWindow::Grid_Loaded(IInspectable const&, RoutedEventArgs const&) {
        winrt::hstring typeName{ winrt::name_of<WindowsUI::Vault>() };

        winrt::Windows::UI::Xaml::Interop::TypeName loginType{
            typeName,
            winrt::Windows::UI::Xaml::Interop::TypeKind::Metadata
        };

        MainFrame().Navigate(loginType);
    }
}
