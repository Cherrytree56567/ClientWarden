#include "pch.h"
#include "Unlock.xaml.h"
#if __has_include("Unlock.g.cpp")
#include "Unlock.g.cpp"
#endif
#include "MainWindow/MainWindow.xaml.h"

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    void Unlock::UnlockButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        FieldError().Text(L"");

        std::string password = winrt::to_string(FieldPassword().Password());
        
        try {
            vault.Unlock(password);
        } catch (const std::runtime_error& e) {
            FieldError().Text(L"Wrong Password");
            return;
        } catch (const std::exception& e) {
            FieldError().Text(L"Wrong Password");
            return;
        } catch (...) {
            FieldError().Text(L"Wrong Password");
            return;
        }

        auto mainWindow = winrt::WindowsUI::implementation::MainWindow::mwstatic;
        mainWindow->postAuth();
    }
}