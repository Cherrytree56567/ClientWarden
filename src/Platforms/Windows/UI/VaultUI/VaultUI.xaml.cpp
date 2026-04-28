#include "pch.h"
#include "VaultUI.xaml.h"
#if __has_include("VaultUI.g.cpp")
#include "VaultUI.g.cpp"
#endif

#include "VaultItem/VaultItem.xaml.h"

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    void VaultUI::NavigationView_Loaded(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e)
    {
        NavView().SelectedItem(NavView().MenuItems().GetAt(0));

        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        ClientWarden::Vault::CipherQuery query(vault);

        std::vector<std::pair<ClientWarden::Vault::CipherType, std::string>> cipherIDs = query.FilterByUnbinned()
                                                                                              .GetCiphers();

        for (auto& cipher : cipherIDs) {
            if (cipher.first == ClientWarden::Vault::CipherType::Login) {
                ClientWarden::Vault::LoginItem loginItem(vault, cipher.second);

                std::string loginName;
                std::string loginUser;
                std::vector<std::string> loginUrl;
                loginItem.GetName(loginName)
                         .GetUsername(loginUser)
                         .GetWebsites(loginUrl);

                std::string lgurl = "ms-appx:///Assets/profile1.png";
                
                if (loginUrl.size() != 0) {
                    lgurl = vault.downloadIcon(loginUrl[0]);
                }

                if (lgurl == "") {
                    lgurl = "ms-appx:///Assets/profile1.png";
                }

                winrt::hstring hloginName = winrt::to_hstring(loginName);
                winrt::hstring hloginUser = winrt::to_hstring(loginUser);
                
                OPENSSL_cleanse(loginName.data(), loginName.size());
                loginName.clear();
                OPENSSL_cleanse(loginUser.data(), loginUser.size());
                loginUser.clear();

                WindowsUI::VaultItem item;
                item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(winrt::to_hstring(lgurl))));
                item.Title(hloginName);
                item.Detail(hloginUser);
                item.Click({ this, &VaultUI::VaultItem_Click });
                item.itemID(winrt::to_hstring(cipher.second));
                item.itemType(L"Login");

                VaultItemList().Children().Append(item);
            } else if (cipher.first == ClientWarden::Vault::CipherType::Card) {
                ClientWarden::Vault::CardItem cardItem(vault, cipher.second);

                std::string cardName;
                std::string cardnam;
                cardItem.GetName(cardName)
                        .GetCardholderName(cardnam);

                winrt::hstring hcardName = winrt::to_hstring(cardName);
                winrt::hstring hcardnam = winrt::to_hstring(cardnam);
                
                OPENSSL_cleanse(cardName.data(), cardName.size());
                cardName.clear();
                OPENSSL_cleanse(cardnam.data(), cardnam.size());
                cardnam.clear();

                WindowsUI::VaultItem item;
                item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/profile1.png")));
                item.Title(hcardName);
                item.Detail(hcardnam);
                item.Click({ this, &VaultUI::VaultItem_Click });
                item.itemID(winrt::to_hstring(cipher.second));
                item.itemType(L"Card");

                VaultItemList().Children().Append(item);
            } else if (cipher.first == ClientWarden::Vault::CipherType::Identity) {
                ClientWarden::Vault::IdentityItem identityItem(vault, cipher.second);

                std::string identityName;
                std::string identityDetail;
                identityItem.GetName(identityName)
                            .GetFirstName(identityDetail);

                winrt::hstring hidentityName = winrt::to_hstring(identityName);
                winrt::hstring hidentityDetail = winrt::to_hstring(identityDetail);
                
                OPENSSL_cleanse(identityName.data(), identityName.size());
                identityName.clear();
                OPENSSL_cleanse(identityDetail.data(), identityDetail.size());
                identityDetail.clear();

                WindowsUI::VaultItem item;
                item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/profile1.png")));
                item.Title(hidentityName);
                item.Detail(hidentityDetail);
                item.Click({ this, &VaultUI::VaultItem_Click });
                item.itemID(winrt::to_hstring(cipher.second));
                item.itemType(L"Identity");

                VaultItemList().Children().Append(item);
            } else if (cipher.first == ClientWarden::Vault::CipherType::Note) {
                ClientWarden::Vault::NoteItem noteItem(vault, cipher.second);

                std::string noteName;
                noteItem.GetName(noteName);

                winrt::hstring hnoteName = winrt::to_hstring(noteName);
                
                OPENSSL_cleanse(noteName.data(), noteName.size());
                noteName.clear();

                WindowsUI::VaultItem item;
                item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/profile1.png")));
                item.Title(hnoteName);
                item.Detail(L"");
                item.Click({ this, &VaultUI::VaultItem_Click });
                item.itemID(winrt::to_hstring(cipher.second));
                item.itemType(L"Note");

                VaultItemList().Children().Append(item);
            } else if (cipher.first == ClientWarden::Vault::CipherType::SSHKey) {
                ClientWarden::Vault::SSHKeyItem sshItem(vault, cipher.second);

                std::string sshName;
                std::string sshDetail;
                sshItem.GetName(sshName)
                       .GetFingerprint(sshDetail);

                winrt::hstring hsshName = winrt::to_hstring(sshName);
                winrt::hstring hsshDetail = winrt::to_hstring(sshDetail);
                
                OPENSSL_cleanse(sshName.data(), sshName.size());
                sshName.clear();
                OPENSSL_cleanse(sshDetail.data(), sshDetail.size());
                sshDetail.clear();

                WindowsUI::VaultItem item;
                item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/profile1.png")));
                item.Title(hsshName);
                item.Detail(hsshDetail);
                item.Click({ this, &VaultUI::VaultItem_Click });
                item.itemID(winrt::to_hstring(cipher.second));
                item.itemType(L"SSHKey");

                VaultItemList().Children().Append(item);
            }
        }
    }

    void VaultUI::VaultItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        auto item = sender.as<WindowsUI::VaultItem>();

        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();
    
        winrt::hstring id = item.itemID();
        winrt::hstring title = item.Title();
        winrt::hstring type = item.itemType();
        winrt::Microsoft::UI::Xaml::Media::ImageSource logo = item.Logo();

        SidebarImage().Source(logo);
        SidebarTitle().Text(title);
        SidebarType().Text(type);
        SidebarId().Text(id);

        SidebarCard().Children().Clear();
        
        if (type == L"Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, winrt::to_string(id));

            std::string username;
            std::string password;
            ClientWarden::Vault::TOTPCode totp;
            std::vector<std::string> websites;
            loginItem.GetUsername(username)
                     .GetPassword(password)
                     .GetTotp(totp)
                     .GetWebsites(websites);
            
            int siz = password.size();

            OPENSSL_cleanse(password.data(), password.size());
            password.clear();

            std::string hidPass;
            
            for (int i = 0; i < siz; i++) {
                hidPass = hidPass + "•";
            }
            
            WindowsUI::GenericField field;
            field.Title(L"Username");
            field.Value(winrt::to_hstring(username));

            SidebarCard().Children().Append(field);
            
            WindowsUI::PasswordField passwdField;
            passwdField.Title(L"Password");
            passwdField.Value(winrt::to_hstring(hidPass));
            passwdField.ShowHide({ this, &VaultUI::LoginPasswordItem_Click });

            SidebarCard().Children().Append(passwdField);

            WindowsUI::WebsiteField websiteField;
            websiteField.Title(L"Websites");

            for (auto& website : websites) {
                winrt::Microsoft::UI::Xaml::Controls::TextBlock tb1;
                tb1.Text(winrt::to_hstring(website));
                websiteField.Value().Append(tb1);

                OPENSSL_cleanse(website.data(), website.size());
                website.clear();
            }

            websites.clear();

            SidebarCard().Children().Append(websiteField);

            loginItem.Close();
        }
    }

    void VaultUI::LoginPasswordItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        auto field = sender.as<WindowsUI::PasswordField>();
        std::string uri = winrt::to_string(field.GetShowHideImage().UriSource().RawUri());

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            std::string password;
            loginItem.GetPassword(password);

            if (uri == "ms-appx:///Assets/ic_fluent_eye_show_24_regular.png") {
                int siz = password.size();

                std::string hidPass;
            
                for (int i = 0; i < siz; i++) {
                    hidPass = hidPass + "•";
                }

                field.Value(winrt::to_hstring(hidPass));
            } else {
                field.Value(winrt::to_hstring(password));
            }

            OPENSSL_cleanse(password.data(), password.size());
            password.clear();

            loginItem.Close();
        }
    }
}
