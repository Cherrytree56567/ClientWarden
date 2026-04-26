#include "pch.h"
#include "VaultUI.xaml.h"
#if __has_include("VaultUI.g.cpp")
#include "VaultUI.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    void VaultUI::NavigationView_Loaded(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e)
    {
        NavView().SelectedItem(NavView().MenuItems().GetAt(0));
    }

    void VaultUI::VaultItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e)
    {

    }
}
