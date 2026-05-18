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
            
            clipboard.Copy(username);

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

            loginItem.GetPassword(password)
                     .Close();
            
            clipboard.Copy(password);

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
            
            clipboard.Copy(code.code);

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

            std::string data = title + " " + firstName + " " + middleName + " " + lastName;
            clipboard.Copy(data);

            OPENSSL_cleanse(title.data(), title.size());
            title.clear();
            OPENSSL_cleanse(firstName.data(), firstName.size());
            firstName.clear();
            OPENSSL_cleanse(middleName.data(), middleName.size());
            middleName.clear();
            OPENSSL_cleanse(lastName.data(), lastName.size());
            lastName.clear();

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
            
            clipboard.Copy(username);

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
            
            clipboard.Copy(company);

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
            
            clipboard.Copy(natIns);

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
            
            clipboard.Copy(passport);

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
            
            clipboard.Copy(licence);

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
            
            clipboard.Copy(email);

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
            
            clipboard.Copy(phone);

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
            
            clipboard.Copy(name);

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
            
            clipboard.Copy(number);

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

            std::string data = expMon + " / " + expYer;

            clipboard.Copy(data);

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
            
            clipboard.Copy(cvv);

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
            
            clipboard.Copy(priv);

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
            
            clipboard.Copy(pub);

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
            
            clipboard.Copy(fing);

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