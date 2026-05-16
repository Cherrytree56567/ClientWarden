#include "pch.h"
#include "PasswordEditField.xaml.h"
#if __has_include("PasswordEditField.g.cpp")
#include "PasswordEditField.g.cpp"
#endif

#include "Vault/PasswordGenerator/PasswordGenerator.h"

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    winrt::hstring PasswordEditField::Title() {
        return FieldName().Text();
    }

    void PasswordEditField::Title(winrt::hstring value) {
        FieldName().Text(value);
    }

    winrt::hstring PasswordEditField::Value() {
        return FieldValue().Password();
    }

    void PasswordEditField::Value(winrt::hstring value) {
        FieldValue().Password(value);
        FieldValue().PasswordRevealMode(winrt::Microsoft::UI::Xaml::Controls::PasswordRevealMode::Visible);
    }

    void PasswordEditField::PassGen_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Input::TappedRoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        ClientWarden::Vault::PasswordGenerator passGen(vault);

        auto selected = PasswordGenMode().SelectedItem().try_as<winrt::Microsoft::UI::Xaml::Controls::ListViewItem>();
        if (!selected) return;

        std::string type = winrt::to_string(winrt::unbox_value<winrt::hstring>(selected.Content()));
        int chars = static_cast<int>(PassGenSlider().Value());

        bool incNum = PassGenNum().IsChecked().Value();
        bool incSym = PassGenSym().IsChecked().Value();
        bool incCap = PassGenCap().IsChecked().Value();

        std::string pass = "";

        if (type == "Random") {
            passGen.Random(chars, incNum, incSym, incCap, pass);
        } else if (type == "Memorable") {
            passGen.Memorable(chars, incCap, pass);
        } else if (type == "Pin") {
            passGen.Pin(chars, pass);
        }

        FieldValue().Password(winrt::to_hstring(pass));

        OPENSSL_cleanse(pass.data(), pass.size());
        pass.clear();
    }

    void PasswordEditField::PassGenList_Changed(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args) {
        if (!PassGenNum() || !PassGenSym() || !PassGenCap()) return;

        auto selected = PasswordGenMode().SelectedItem().try_as<winrt::Microsoft::UI::Xaml::Controls::ListViewItem>();
        if (!selected) return;

        std::string value = winrt::to_string(winrt::unbox_value<winrt::hstring>(selected.Content()));

        if (value == "Random") {
            PassGenNum().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            PassGenSym().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            PassGenCap().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
        } else if (value == "Pin") {
            PassGenNum().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            PassGenSym().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            PassGenCap().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
        } else if (value == "Memorable") {
            PassGenNum().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            PassGenSym().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            PassGenCap().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
        }
    }

    void PasswordEditField::DisablePasswordGen() {
        PassGenBtn().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
        PassGenSlider().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
        PassGenOptions().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
        PasswordGenMode().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
        FieldValue().Margin(winrt::Microsoft::UI::Xaml::Thickness{ -10, 2, -10, -8 });
    }
}