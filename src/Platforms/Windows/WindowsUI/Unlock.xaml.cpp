#include "pch.h"
#include "Unlock.xaml.h"
#if __has_include("Unlock.g.cpp")
#include "Unlock.g.cpp"
#endif

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    int32_t Unlock::MyProperty()
    {
        throw hresult_not_implemented();
    }

    void Unlock::MyProperty(int32_t /* value */)
    {
        throw hresult_not_implemented();
    }
}

void winrt::WindowsUI::implementation::Unlock::UnlockButton_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e)
{

}