#include "pch.h"
#include "Vault.xaml.h"
#if __has_include("Vault.g.cpp")
#include "Vault.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    int32_t Vault::MyProperty()
    {
        throw hresult_not_implemented();
    }

    void Vault::MyProperty(int32_t /* value */)
    {
        throw hresult_not_implemented();
    }
}

void winrt::WindowsUI::implementation::Vault::NavigationView_Loaded(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e)
{
    NavView().SelectedItem(AllItems());
}
