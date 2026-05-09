#include "pch.h"
#include "VaultUI.xaml.h"

#include "VaultItem/VaultItem.xaml.h"

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    void VaultUI::Username_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string username;

            loginItem.GetUsername(username)
                     .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(username));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(username.data(), username.size());
            username.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::Password_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string password;

            loginItem.GetUsername(password)
                     .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(password));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(password.data(), password.size());
            password.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::TOTP_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            /*
             * SECRET DATA
            */
            ClientWarden::Vault::TOTPCode code;

            loginItem.GetTotp(code)
                     .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(code.code));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(code.code.data(), code.code.size());
            code.code.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::NameIdentity_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string title;
            std::string firstName;
            std::string middleName;
            std::string lastName;

            identityItem.GetTitle(title)
                        .GetFirstName(firstName)
                        .GetMiddleName(middleName)
                        .GetLastName(lastName)
                        .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(title + " " + firstName + " " + middleName + " " + lastName));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(title.data(), title.size());
            title.clear();
            OPENSSL_cleanse(firstName.data(), firstName.size());
            firstName.clear();
            OPENSSL_cleanse(middleName.data(), middleName.size());
            middleName.clear();
            OPENSSL_cleanse(lastName.data(), lastName.size());
            lastName.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::UsernameIdentity_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string username;

            identityItem.GetUsername(username)
                        .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(username));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(username.data(), username.size());
            username.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::CompanyIdentity_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string company;

            identityItem.GetCompany(company)
                        .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(company));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(company.data(), company.size());
            company.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::NatInsIdentity_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string natIns;

            identityItem.GetSSN(natIns)
                        .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(natIns));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(natIns.data(), natIns.size());
            natIns.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::PassportIdentity_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string passport;

            identityItem.GetPassportNumber(passport)
                        .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(passport));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(passport.data(), passport.size());
            passport.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::LicenceIdentity_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string licence;

            identityItem.GetLicenceNumber(licence)
                        .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(licence));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(licence.data(), licence.size());
            licence.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::EmailIdentity_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string email;

            identityItem.GetEmail(email)
                        .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(email));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(email.data(), email.size());
            email.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::PhoneIdentity_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string phone;

            identityItem.GetPhone(phone)
                        .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(phone));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(phone.data(), phone.size());
            phone.clear();

            CopyTip().IsOpen(true);

            /*
             * TODO: Close after 3s
            */
            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }
    
    void VaultUI::CardholderCard_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string name;

            cardItem.GetCardholderName(name)
                    .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(name));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(name.data(), name.size());
            name.clear();

            CopyTip().IsOpen(true);

            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }
    
    void VaultUI::NumberCard_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string number;

            cardItem.GetNumber(number)
                    .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(number));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(number.data(), number.size());
            number.clear();

            CopyTip().IsOpen(true);

            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }
    
    void VaultUI::ExpirationCard_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string expMon;
            std::string expYer;

            cardItem.GetExpMonth(expMon)
                    .GetExpYear(expYer)
                    .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(expMon + " / " + expYer));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(expMon.data(), expMon.size());
            expMon.clear();
            OPENSSL_cleanse(expYer.data(), expYer.size());
            expYer.clear();

            CopyTip().IsOpen(true);

            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }
    
    void VaultUI::CVVCard_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string cvv;

            cardItem.GetCode(cvv)
                    .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(cvv));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(cvv.data(), cvv.size());
            cvv.clear();

            CopyTip().IsOpen(true);

            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::PrivSSH_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string priv;

            sshkeyItem.GetPrivateKey(priv)
                      .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(priv));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(priv.data(), priv.size());
            priv.clear();

            CopyTip().IsOpen(true);

            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::PubSSH_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string pub;

            sshkeyItem.GetPublicKey(pub)
                      .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(pub));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(pub.data(), pub.size());
            pub.clear();

            CopyTip().IsOpen(true);

            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }

    void VaultUI::FingSSH_Copy(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string fing;

            sshkeyItem.GetFingerprint(fing)
                      .Close();
            
            auto data = winrt::Windows::ApplicationModel::DataTransfer::DataPackage();
            data.SetText(winrt::to_hstring(fing));
            winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContent(data);

            OPENSSL_cleanse(fing.data(), fing.size());
            fing.clear();

            CopyTip().IsOpen(true);

            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
            std::thread t([this, dispatcher]() {
                std::this_thread::sleep_for(std::chrono::seconds(3));
                dispatcher.TryEnqueue([this]() {
                    CopyTip().IsOpen(false);
                });
            });
            t.detach();
        }
    }
}