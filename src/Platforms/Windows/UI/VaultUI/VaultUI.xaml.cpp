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
    VaultUI::VaultUI() : vault(ClientWarden::Vault::Vault::Instance()) {
        if (!logger) {
            logger = spdlog::stdout_color_mt("ClientWarden::Windows::UI");
        }
        // Xaml objects should not call InitializeComponent during construction.
        // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
    }
    
    void VaultUI::NavigationView_Loaded(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        NavView().SelectedItem(NavView().MenuItems().GetAt(0));

        if (!vault.settingsData["clipboardClear"].is_number()) {
            vault.settingsData["clipboardClear"] = 30;
        }

        clipboard.SetDelay(vault.settingsData["clipboardClear"]);

        StartTOTPThread();

        ClientWarden::Vault::CipherQuery query(vault);

        std::vector<std::pair<ClientWarden::Vault::CipherType, std::string>> cipherIDs = query.FilterByUnbinned()
                                                                                              .GetCiphers();

        VaultItemList().Children().Clear();

        PopulateItemsList(cipherIDs);

        FolderPicker().AddOption(winrt::to_hstring(""));

        std::vector<std::string> folders = vault.GetFolders();

        for (auto folder : folders) {
            DisplayFolder(folder);
        }

        FolderPicker().GetComboBox().SelectionChanged({ this, &VaultUI::FolderPickerSelectionChanged });
    }

    winrt::fire_and_forget VaultUI::SidebarAttachment_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            std::string id = winrt::to_string(SidebarId().Text());
            std::string type = winrt::to_string(SidebarType().Text());

            ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

            HWND hwnd = GetActiveWindow();

            winrt::Windows::Storage::Pickers::FileOpenPicker picker;
            picker.as<IInitializeWithWindow>()->Initialize(hwnd);

            picker.SuggestedStartLocation(winrt::Windows::Storage::Pickers::PickerLocationId::Downloads);
            picker.FileTypeFilter().Append(L"*");

            auto file = co_await picker.PickSingleFileAsync();
            if (!file) co_return;

            auto stream = co_await file.OpenReadAsync();
            winrt::Windows::Storage::Streams::DataReader reader(stream);
            co_await reader.LoadAsync(static_cast<uint32_t>(stream.Size()));

            std::vector<uint8_t> contents(stream.Size());
            reader.ReadBytes(contents);

            std::string fileName = winrt::to_string(file.Name());
            std::string fileContents(contents.begin(), contents.end());

            auto attId = vault.OnlineAddAttachment(id, fileContents, fileName);

            if (!attId) co_return;

            WindowsUI::AttachmentField attField;
            attField.Title(file.Name());
            attField.Value(winrt::to_hstring(attId.value()));
            attField.Download([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                auto id = winrt::to_string(field.Value());

                ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                ClientWarden::Vault::LoginItem loginItem(vault, winrt::to_string(SidebarId().Text()));

                std::string attCont;
                    
                loginItem.GetAttachment(id, attCont)
                         .Close();
                    
                HWND hwnd = GetActiveWindow();
                winrt::Windows::Storage::Pickers::FileSavePicker picker;
                picker.as<IInitializeWithWindow>()->Initialize(hwnd);

                picker.SuggestedStartLocation(winrt::Windows::Storage::Pickers::PickerLocationId::Downloads);
                picker.SuggestedFileName(field.Title());
                picker.FileTypeChoices().Insert(L"All Files", winrt::single_threaded_vector<winrt::hstring>({ L"." }));

                auto file = co_await picker.PickSaveFileAsync();
                if (!file) {
                    OPENSSL_cleanse(attCont.data(), attCont.size());
                    co_return;
                }

                auto stream = co_await file.OpenAsync(winrt::Windows::Storage::FileAccessMode::ReadWrite);
                winrt::Windows::Storage::Streams::DataWriter writer(stream);
                writer.WriteBytes(winrt::array_view<const uint8_t>(reinterpret_cast<const uint8_t*>(attCont.data()), reinterpret_cast<const uint8_t*>(attCont.data()) + attCont.size()));
                co_await writer.StoreAsync();
                co_await writer.FlushAsync();
                writer.DetachStream();

                OPENSSL_cleanse(attCont.data(), attCont.size());
            });

            SidebarAttachments().Children().Append(attField);

            OPENSSL_cleanse(fileName.data(), fileName.size());
            fileName.clear();

            OPENSSL_cleanse(fileContents.data(), fileContents.size());
            fileContents.clear();

            co_return;
        } catch (...) {
            /*
             * TODO: Add Logger as part of Code Cleanup
            */
        }
        co_return;
    }

    void VaultUI::NewItemDropdown_SelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& e) {
        auto box = sender.as<winrt::Microsoft::UI::Xaml::Controls::ComboBox>();
        auto selected = box.SelectedItem().as<winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem>();
        std::string value = winrt::to_string(selected.Content().as<winrt::hstring>());

        std::string type = winrt::to_string(SidebarType().Text());

        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        if (value == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault);

            std::string newName = "New Login";
            std::string id;

            loginItem.SetName(newName)
                     .GetId(id)
                     .Commit();
            
            PopulateItem({ClientWarden::Vault::CipherType::Login, id});
        } else if (value == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault);

            std::string newName = "New Card";
            std::string id;

            cardItem.SetName(newName)
                    .GetId(id)
                    .Commit();
            
            PopulateItem({ClientWarden::Vault::CipherType::Card, id});
        } else if (value == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault);

            std::string newName = "New Identity";
            std::string id;

            identityItem.SetName(newName)
                        .GetId(id)
                        .Commit();
            
            PopulateItem({ClientWarden::Vault::CipherType::Identity, id});
        } else if (value == "Note") {
            ClientWarden::Vault::NoteItem noteItem(vault);

            std::string newName = "New Note";
            std::string id;

            noteItem.SetName(newName)
                    .GetId(id)
                    .Commit();
            
            PopulateItem({ClientWarden::Vault::CipherType::Note, id});
        } else if (value == "SSH Key") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault);

            std::string newName = "New SSH Key";
            std::string id;

            sshkeyItem.SetName(newName)
                      .GetId(id)
                      .Commit();
            
            PopulateItem({ClientWarden::Vault::CipherType::SSHKey, id});
        }

        auto lastItem = VaultItemList().Children().GetAt(VaultItemList().Children().Size() - 1).as<WindowsUI::VaultItem>();

        PopulateSidePane(lastItem.itemID(), lastItem.Title(), lastItem.itemType(), lastItem.Logo());
        
        SidebarEdit_Click(
            winrt::box_value(winrt::hstring{}),
            winrt::Microsoft::UI::Xaml::RoutedEventArgs{}
        );
    }

    void VaultUI::NavigationView_SelectionChanged(winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender, winrt::Microsoft::UI::Xaml::Controls::NavigationViewSelectionChangedEventArgs const& args) {
        auto selectedItem = args.SelectedItem().try_as<winrt::Microsoft::UI::Xaml::Controls::NavigationViewItem>();

        if (!selectedItem) {
            return;
        }

        SidebarEmptyMode();

        std::string tag = winrt::to_string(selectedItem.Name());

        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();
        ClientWarden::Vault::CipherQuery query(vault);

        query.FilterNameByRegex(winrt::to_string(SearchBar().Text()));

        std::vector<std::pair<ClientWarden::Vault::CipherType, std::string>> cipherIDs;

        PermButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
        RestoreButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
        DeleteButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);

        if (tag == "AllItems") {
            cipherIDs = query.FilterByUnbinned()
                             .GetCiphers();
        } else if (tag == "Fav") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByFavorites()
                             .GetCiphers();
        } else if (tag == "Del") {
            cipherIDs = query.FilterByBinned()
                             .GetCiphers();
            PermButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            RestoreButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            DeleteButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
        } else if (tag == "Login") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::Login)
                             .GetCiphers();
        } else if (tag == "Card") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::Card)
                             .GetCiphers();
        } else if (tag == "Identity") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::Identity)
                             .GetCiphers();
        } else if (tag == "SecNote") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::Note)
                             .GetCiphers();
        } else if (tag == "SSH") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::SSHKey)
                             .GetCiphers();
        } else if (tag == "NewFold") {
            if (!vault.checkConnectivity()) {
                return;
            }
            ClientWarden::Vault::Folder folderItem(vault);

            /*
             * SECRET DATA
            */
            std::string folderName = "New Folder";
            std::string folder = "";

            folderItem.SetName(folderName)
                      .GetID(folder)
                      .Commit();
            
            DisplayFolder(folder);
            return;
        } else if (tag == "SettingsItem") {

        } else {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByFolder(tag)
                             .GetCiphers();
        }

        VaultItemList().Children().Clear();

        PopulateItemsList(cipherIDs);
    }

    void VaultUI::SearchBox_TextChanged(winrt::Microsoft::UI::Xaml::Controls::AutoSuggestBox const& sender, winrt::Microsoft::UI::Xaml::Controls::AutoSuggestBoxTextChangedEventArgs const& args) {
        auto selectedItem = NavView().SelectedItem().try_as<winrt::Microsoft::UI::Xaml::Controls::NavigationViewItem>();

        if (!selectedItem) {
            return;
        }

        std::string tag = winrt::to_string(selectedItem.Name());

        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        ClientWarden::Vault::CipherQuery query(vault);

        query.FilterNameByRegex(winrt::to_string(SearchBar().Text()));

        std::vector<std::pair<ClientWarden::Vault::CipherType, std::string>> cipherIDs;

        if (tag == "AllItems") {
            cipherIDs = query.FilterByUnbinned()
                             .GetCiphers();
        } else if (tag == "Fav") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByFavorites()
                             .GetCiphers();
        } else if (tag == "Del") {
            cipherIDs = query.FilterByBinned()
                             .GetCiphers();
        } else if (tag == "Login") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::Login)
                             .GetCiphers();
        } else if (tag == "Card") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::Card)
                             .GetCiphers();
        } else if (tag == "Identity") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::Identity)
                             .GetCiphers();
        } else if (tag == "SecNote") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::Note)
                             .GetCiphers();
        } else if (tag == "SSH") {
            cipherIDs = query.FilterByUnbinned()
                             .FilterByType(ClientWarden::Vault::CipherType::SSHKey)
                             .GetCiphers();
        }

        VaultItemList().Children().Clear();

        PopulateItemsList(cipherIDs);
    }

    void VaultUI::PopulateItem(std::pair<ClientWarden::Vault::CipherType, std::string> cipherId) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();
        if (cipherId.first == ClientWarden::Vault::CipherType::Login) {
            ClientWarden::Vault::LoginItem loginItem(vault, cipherId.second);

            /*
             * SECRET DATA
            */
            std::string loginName;
            std::string loginUser;
            std::vector<std::string> loginUrl;

            loginItem.GetName(loginName)
                     .GetUsername(loginUser)
                     .GetWebsites(loginUrl)
                     .Close();

            std::string lgurl = "ms-appx:///Assets/ic_fluent_globe_24_filled.png";
                
            if (loginUrl.size() != 0) {
                lgurl = vault.downloadIcon(loginUrl[0]);
            }

            if (lgurl == "") {
                lgurl = "ms-appx:///Assets/ic_fluent_globe_24_filled.png";
            }

            /*
             * SECRET DATA
            */
            winrt::hstring hloginName = winrt::to_hstring(loginName);
            winrt::hstring hloginUser = winrt::to_hstring(loginUser);
                
            OPENSSL_cleanse(loginName.data(), loginName.size());
            loginName.clear();
            OPENSSL_cleanse(loginUser.data(), loginUser.size());
            loginUser.clear();
                
            for (auto& uri : loginUrl) {
                OPENSSL_cleanse(uri.data(), uri.size());
                uri.clear();
            }
            loginUrl.clear();

            WindowsUI::VaultItem item;
            item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(winrt::to_hstring(lgurl))));
            item.Title(hloginName);
            item.Detail(hloginUser);
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(cipherId.second));
            item.itemType(L"Login");

            VaultItemList().Children().Append(item);
        } else if (cipherId.first == ClientWarden::Vault::CipherType::Card) {
            ClientWarden::Vault::CardItem cardItem(vault, cipherId.second);

            /*
             * SECRET DATA
            */
            std::string cardName;
            std::string cardnam;
            std::string cardBrand;

            cardItem.GetName(cardName)
                    .GetCardholderName(cardnam)
                    .GetBrand(cardBrand)
                    .Close();
              
            auto hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_credit_card_person_24_regular.png"));
            if (cardBrand == "Amex") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-amex-brands-solid.png"));
            } else if (cardBrand == "Visa") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-visa-brands-solid.png"));
            } else if (cardBrand == "Mastercard") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-mastercard-brands-solid.png"));
            } else if (cardBrand == "Discover") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-discover-brands-solid.png"));
            } else if (cardBrand == "Diners Club") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-diners-club-brands-solid.png"));
            } else if (cardBrand == "JCB") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-jcb-brands-solid.png"));
            } else {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_credit_card_person_24_regular.png"));
            }

            /*
             * SECRET DATA
            */
            winrt::hstring hcardName = winrt::to_hstring(cardName);
            winrt::hstring hcardnam = winrt::to_hstring(cardnam);
                
            OPENSSL_cleanse(cardName.data(), cardName.size());
            cardName.clear();
            OPENSSL_cleanse(cardnam.data(), cardnam.size());
            cardnam.clear();
            OPENSSL_cleanse(cardBrand.data(), cardBrand.size());
            cardBrand.clear();

            WindowsUI::VaultItem item;
            item.Logo(hlogo);
            item.Title(hcardName);
            item.Detail(hcardnam);
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(cipherId.second));
            item.itemType(L"Card");

            VaultItemList().Children().Append(item);
        } else if (cipherId.first == ClientWarden::Vault::CipherType::Identity) {
            ClientWarden::Vault::IdentityItem identityItem(vault, cipherId.second);

            /*
             * SECRET DATA
            */
            std::string identityName;
            std::string identityDetail;

            identityItem.GetName(identityName)
                        .GetFirstName(identityDetail)
                        .Close();

            /*
             * SECRET DATA
            */
            winrt::hstring hidentityName = winrt::to_hstring(identityName);
            winrt::hstring hidentityDetail = winrt::to_hstring(identityDetail);
                
            OPENSSL_cleanse(identityName.data(), identityName.size());
            identityName.clear();
            OPENSSL_cleanse(identityDetail.data(), identityDetail.size());
            identityDetail.clear();

            WindowsUI::VaultItem item;
            item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_share_screen_person_24_regular.png")));
            item.Title(hidentityName);
            item.Detail(hidentityDetail);
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(cipherId.second));
            item.itemType(L"Identity");

            VaultItemList().Children().Append(item);
        } else if (cipherId.first == ClientWarden::Vault::CipherType::Note) {
            ClientWarden::Vault::NoteItem noteItem(vault, cipherId.second);

            /*
             * SECRET DATA
            */
            std::string noteName;

            noteItem.GetName(noteName)
                    .Close();

            /*
             * SECRET DATA
            */
            winrt::hstring hnoteName = winrt::to_hstring(noteName);
                
            OPENSSL_cleanse(noteName.data(), noteName.size());
            noteName.clear();

            WindowsUI::VaultItem item;
            item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_note_24_regular.png")));
            item.Title(hnoteName);
            item.Detail(L"");
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(cipherId.second));
            item.itemType(L"Note");

            VaultItemList().Children().Append(item);
        } else if (cipherId.first == ClientWarden::Vault::CipherType::SSHKey) {
            ClientWarden::Vault::SSHKeyItem sshItem(vault, cipherId.second);

            /*
             * SECRET DATA
            */
            std::string sshName;
            std::string sshDetail;

            sshItem.GetName(sshName)
                   .GetFingerprint(sshDetail)
                   .Close();

            /*
             * SECRET DATA
            */
            winrt::hstring hsshName = winrt::to_hstring(sshName);
            winrt::hstring hsshDetail = winrt::to_hstring(sshDetail);
                
            OPENSSL_cleanse(sshName.data(), sshName.size());
            sshName.clear();
            OPENSSL_cleanse(sshDetail.data(), sshDetail.size());
            sshDetail.clear();

            WindowsUI::VaultItem item;
            item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_key_24_regular.png")));
            item.Title(hsshName);
            item.Detail(hsshDetail);
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(cipherId.second));
            item.itemType(L"SSHKey");

            VaultItemList().Children().Append(item);
        }
    }

    void VaultUI::PopulateItemsList(std::vector<std::pair<ClientWarden::Vault::CipherType, std::string>> cipherIDs) {
        for (auto& cipher : cipherIDs) {
            PopulateItem(cipher);
        }
    }

    void VaultUI::SidebarSave_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        if (!isEdit) return;
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string name = winrt::to_string(SidebarTitleBox().Text());
        std::string ItemName = name;
        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());
        std::string detail = "";

        std::string notes = "";
        std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> fields;

        notes = winrt::to_string(SidebarNotesEdit().Text());

        for (auto child : SidebarFields().Children()) {
            if (auto typ = child.try_as<WindowsUI::TextEditField>()) {
                fields.push_back({ClientWarden::Vault::CustomFieldType::Text, winrt::to_string(typ.Title()), winrt::to_string(typ.Value())});
            } else if (auto typ = child.try_as<WindowsUI::HiddenEditField>()) {
                fields.push_back({ClientWarden::Vault::CustomFieldType::Hidden, winrt::to_string(typ.Title()), winrt::to_string(typ.Value())});
            } else if (auto typ = child.try_as<WindowsUI::CheckboxEditField>()) {
                std::string val = "false";
                if (typ.Value()) {
                    val = "true";
                }
                fields.push_back({ClientWarden::Vault::CustomFieldType::Checkbox, winrt::to_string(typ.Title()), val});
            } else if (auto typ = child.try_as<WindowsUI::LinkedEditField>()) {
                std::string val = "100";
                if (typ.Value() == L"Username") {
                    val = "100";
                } else if (typ.Value() == L"Password") {
                    val = "101";
                }
                fields.push_back({ClientWarden::Vault::CustomFieldType::Linked, winrt::to_string(typ.Title()), val});
            }
        }

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string username;
            std::string password;
            std::string totp;

            std::vector<std::string> websites;

            for (auto child : SidebarCard().Children()) {
                if (auto field = child.try_as<WindowsUI::GenericEditField>()) {
                    if (field.Title() == L"Username") {
                        username = winrt::to_string(field.Value());
                        detail = winrt::to_string(field.Value());
                    }
                } else if (auto field = child.try_as<WindowsUI::PasswordEditField>()) {
                    if (field.Title() == L"Password") {
                        password = winrt::to_string(field.Value());
                    } else if (field.Title() == L"One Time Password") {
                        totp = winrt::to_string(field.Value());
                    }
                } else if (auto field = child.try_as<WindowsUI::WebsiteEditField>()) {
                    if (field.Title() == L"Websites") {
                        auto fields = field.GetFields();
                        for (auto web : fields) {
                            websites.push_back(winrt::to_string(web));
                        }
                    }
                }
            }

            std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> locFields;
            std::vector<std::string> locWebsites;

            loginItem.SetName(name)
                     .SetUsername(username)
                     .SetPassword(password)
                     .SetTotp(totp)
                     .GetWebsites(locWebsites)
                     .SetNotes(notes)
                     .GetFields(locFields);
            
            for (auto [type, name, value] : locFields) {
                loginItem.RemoveField(name);
                OPENSSL_cleanse(name.data(), name.size());
                name.clear();
                OPENSSL_cleanse(value.data(), value.size());
                value.clear();
            }

            for (auto field : locWebsites) {
                loginItem.RemoveWebsite(field);
                OPENSSL_cleanse(field.data(), field.size());
                field.clear();
            }

            for (auto [type, name, value] : fields) {
                loginItem.AddField(type, name, value);
            }

            for (auto field : websites) {
                loginItem.AddWebsite(field);
            }

            loginItem.Commit();
        } else if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            std::string title;
            std::string firstName;
            std::string middleName;
            std::string lastName;
            std::string username;
            std::string company;
            std::string nationalInsuranceNum;
            std::string passportNum;
            std::string licenceNum;
            std::string email;
            std::string phone;
            std::string address1;
            std::string address2;
            std::string address3;
            std::string city;
            std::string county;
            std::string postalCode;
            std::string country;

            for (auto child : SidebarCard().Children()) {
                if (auto field = child.try_as<WindowsUI::GenericEditField>()) {
                    if (field.Title() == L"Title") {
                        title = winrt::to_string(field.Value());
                    } else if (field.Title() == L"First Name") {
                        firstName = winrt::to_string(field.Value());
                        detail = winrt::to_string(field.Value()); 
                    } else if (field.Title() == L"Middle Name") {
                        middleName = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Last Name") {
                        lastName = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Username") {
                        username = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Company") {
                        company = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Licence Number") {
                        licenceNum = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Email") {
                        email = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Phone") {
                        phone = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Address 1") {
                        address1 = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Address 2") {
                        address2 = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Address 3") {
                        address3 = winrt::to_string(field.Value());
                    } else if (field.Title() == L"City") {
                        city = winrt::to_string(field.Value());
                    } else if (field.Title() == L"State") {
                        county = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Postal Code") {
                        postalCode = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Country") {
                        country = winrt::to_string(field.Value());
                    }
                } else if (auto field = child.try_as<WindowsUI::PasswordEditField>()) {
                    if (field.Title() == L"National Insurance Number") {
                        nationalInsuranceNum = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Passport Number") {
                        passportNum = winrt::to_string(field.Value());
                    }
                }
            }

            std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> locFields;

            identityItem.SetTitle(title)
                        .SetFirstName(firstName)
                        .SetMiddleName(middleName)
                        .SetLastName(lastName)
                        .SetUsername(username)
                        .SetCompany(company)
                        .SetSSN(nationalInsuranceNum)
                        .SetPassportNumber(passportNum)
                        .SetLicenceNumber(licenceNum)
                        .SetEmail(email)
                        .SetPhone(phone)
                        .SetAddress1(address1)
                        .SetAddress2(address2)
                        .SetAddress3(address3)
                        .SetCity(city)
                        .SetState(county)
                        .SetPostalCode(postalCode)
                        .SetCountry(country)
                        .SetName(name)
                        .SetNotes(notes)
                        .GetFields(locFields);
            
            for (auto field : locFields) {
                identityItem.RemoveField(std::get<1>(field));
            }

            for (auto field : fields) {
                identityItem.AddField(std::get<0>(field), std::get<1>(field), std::get<2>(field));
            }

            identityItem.Commit();
        } else if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            std::string cardholderName;
            std::string number;
            std::string expirationMonth;
            std::string expirationYear;
            std::string cvv;
            std::string brand;

            for (auto child : SidebarCard().Children()) {
                if (auto field = child.try_as<WindowsUI::GenericEditField>()) {
                    if (field.Title() == L"Cardholder Name") {
                        cardholderName = winrt::to_string(field.Value());
                        detail = winrt::to_string(field.Value()); 
                    } else if (field.Title() == L"Expiration Month") {
                        expirationMonth = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Expiration Year") {
                        expirationYear = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Brand") {
                        brand = winrt::to_string(field.Value());
                    }
                } else if (auto field = child.try_as<WindowsUI::PasswordEditField>()) {
                    if (field.Title() == L"Number") {
                        number = winrt::to_string(field.Value());
                    } else if (field.Title() == L"CVV") {
                        cvv = winrt::to_string(field.Value());
                    }
                }
            }

            std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> locFields;

            cardItem.SetCardholderName(cardholderName)
                    .SetNumber(number)
                    .SetExpMonth(expirationMonth)
                    .SetExpYear(expirationYear)
                    .SetCode(cvv)
                    .SetBrand(brand)
                    .SetName(name)
                    .SetNotes(notes)
                    .GetFields(locFields);
            
            for (auto field : locFields) {
                cardItem.RemoveField(std::get<1>(field));
            }

            for (auto field : fields) {
                cardItem.AddField(std::get<0>(field), std::get<1>(field), std::get<2>(field));
            }

            cardItem.Commit();
        } else if (type == "Note") {
            ClientWarden::Vault::NoteItem noteItem(vault, id);

            std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> locFields;

            noteItem.SetNotes(notes)
                    .SetName(name)
                    .GetFields(locFields);
            
            for (auto field : locFields) {
                noteItem.RemoveField(std::get<1>(field));
            }

            for (auto field : fields) {
                noteItem.AddField(std::get<0>(field), std::get<1>(field), std::get<2>(field));
            }

            noteItem.Commit();
        } else if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            std::string privKey;
            std::string pubKey;
            std::string fingerprint;

            for (auto child : SidebarCard().Children()) {
                if (auto field = child.try_as<WindowsUI::GenericEditField>()) {
                    if (field.Title() == L"Public Key") {
                        pubKey = winrt::to_string(field.Value());
                    } else if (field.Title() == L"Fingerprint") {
                        fingerprint = winrt::to_string(field.Value());
                        detail = winrt::to_string(field.Value()); 
                    }
                } else if (auto field = child.try_as<WindowsUI::PasswordEditField>()) {
                    if (field.Title() == L"Private Key") {
                        privKey = winrt::to_string(field.Value());
                    }
                }
            }

            std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> locFields;

            sshkeyItem.SetPrivateKey(privKey)
                      .SetPublicKey(pubKey)
                      .SetFingerprint(fingerprint)
                      .SetName(name)
                      .SetNotes(notes)
                      .GetFields(locFields);
            
            for (auto field : locFields) {
                sshkeyItem.RemoveField(std::get<1>(field));
            }

            for (auto field : fields) {
                sshkeyItem.AddField(std::get<0>(field), std::get<1>(field), std::get<2>(field));
            }

            sshkeyItem.Commit();
        }

        for (auto child : VaultItemList().Children()) {
            if (auto item = child.try_as<winrt::WindowsUI::VaultItem>()) {
                if (winrt::to_string(item.itemID()) == id) {
                    item.Title(winrt::to_hstring(ItemName));
                    item.Detail(winrt::to_hstring(detail));
                    break;
                }
            }
        }

        SidebarTitle().Text(SidebarTitleBox().Text());

        OPENSSL_cleanse(ItemName.data(), ItemName.size());
        ItemName.clear();
        OPENSSL_cleanse(detail.data(), detail.size());
        detail.clear();

        SidebarViewMode();

        PopulateSidePane(SidebarId().Text(), SidebarTitle().Text(), SidebarType().Text(), SidebarImage().Source());
    }
    
    void VaultUI::FieldsDropdown_SelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& e) {
        auto box = sender.as<winrt::Microsoft::UI::Xaml::Controls::ComboBox>();
        auto selected = box.SelectedItem().as<winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem>();
        std::string value = winrt::to_string(selected.Content().as<winrt::hstring>());

        std::string type = winrt::to_string(SidebarType().Text());

        if (value == "Text") {
            WindowsUI::TextEditField texField;
            texField.Title(L"");
            texField.Value(L"");
            texField.DeleteField([this, texField](auto, auto) {
                auto parent = SidebarFields();
                uint32_t index;
                parent.Children().IndexOf(texField, index);
                parent.Children().RemoveAt(index);
            });
            SidebarFields().Children().Append(texField);
        } else if (value == "Hidden") {
            WindowsUI::HiddenEditField hidField;
            hidField.Title(L"");
            hidField.Value(L"");
            hidField.DeleteField([this, hidField](auto, auto) {
                auto parent = SidebarFields();
                uint32_t index;
                parent.Children().IndexOf(hidField, index);
                parent.Children().RemoveAt(index);
            });
            SidebarFields().Children().Append(hidField);
        } else if (value == "Checkbox") {
            WindowsUI::CheckboxEditField checkField;
            checkField.Title(L"");
            checkField.Value(false);
            checkField.DeleteField([this, checkField](auto, auto) {
                auto parent = SidebarFields();
                uint32_t index;
                parent.Children().IndexOf(checkField, index);
                parent.Children().RemoveAt(index);
            });
            SidebarFields().Children().Append(checkField);
        } else if (value == "Linked") {
            WindowsUI::LinkedEditField linkedField;
            linkedField.Title(L"");
            if (type == "Login") {
                linkedField.AddOption(L"Username");
                linkedField.AddOption(L"Password");
                linkedField.Value(L"Username");
            }
            linkedField.DeleteField([this, linkedField](auto, auto) {
                auto parent = SidebarFields();
                uint32_t index;
                parent.Children().IndexOf(linkedField, index);
                parent.Children().RemoveAt(index);
            });
            SidebarFields().Children().Append(linkedField);
        }
    }

    void VaultUI::SidebarCancel_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        SidebarViewMode();

        PopulateSidePane(SidebarId().Text(), SidebarTitle().Text(), SidebarType().Text(), SidebarImage().Source());
    }

    void VaultUI::SidebarEdit_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        SidebarEditMode();

        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        SidebarCard().Children().Clear();
        SidebarFields().Children().Clear();

        FolderPicker().GetComboBox().IsEnabled(true);
        FolderPicker().GetComboBox().ClearValue(winrt::Microsoft::UI::Xaml::Controls::Control::BorderBrushProperty());
        FolderPicker().GetComboBox().ClearValue(winrt::Microsoft::UI::Xaml::Controls::Control::BackgroundProperty());

        /*
         * SECRET DATA
        */
        std::string notes = "";
        std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> fields;
        std::vector<std::string> attachIds;
        bool fav = false;
        
        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string username;
            std::string password;
            std::string totp;

            std::vector<std::string> websites;

            loginItem.GetUsername(username)
                     .GetPassword(password)
                     .GetTotpSecret(totp)
                     .GetWebsites(websites)
                     .GetNotes(notes)
                     .GetFields(fields)
                     .GetFavorite(fav)
                     .GetAttachmentIDs(attachIds);
            
            for (auto& attach : attachIds) {
                std::string attname;

                loginItem.GetAttachmentName(attach, attname);

                WindowsUI::AttachmentEditField attField;
                attField.Title(winrt::to_hstring(attname));
                attField.Value(winrt::to_hstring(attach));
                attField.Bin([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                    auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                    auto id = winrt::to_string(field.Value());

                    ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                    ClientWarden::Vault::LoginItem loginItem(vault, winrt::to_string(SidebarId().Text()));
                    
                    loginItem.RemoveAttachment(id)
                             .Close();
                    
                    co_return;
                });

                OPENSSL_cleanse(attname.data(), attname.size());
                attname.clear();

                SidebarAttachments().Children().Append(attField);
            }

            loginItem.Close();
            
            WindowsUI::GenericEditField field;
            field.Title(L"Username");
            field.Value(winrt::to_hstring(username));

            SidebarCard().Children().Append(field);
            
            WindowsUI::PasswordEditField passwdField;
            passwdField.Title(L"Password");
            passwdField.Value(winrt::to_hstring(password));

            SidebarCard().Children().Append(passwdField);

            WindowsUI::PasswordEditField totpField;
            totpField.Title(L"One Time Password");
            totpField.Value(winrt::to_hstring(totp));
            totpField.DisablePasswordGen();

            SidebarCard().Children().Append(totpField);

            WindowsUI::WebsiteEditField websiteField;
            websiteField.Title(L"Websites");

            for (auto& website : websites) {
                winrt::Microsoft::UI::Xaml::Controls::TextBlock tb1;
                tb1.Text(winrt::to_hstring(website));
                websiteField.AddField(winrt::to_hstring(website));

                OPENSSL_cleanse(website.data(), website.size());
                website.clear();
            }

            websites.clear();

            SidebarCard().Children().Append(websiteField);

            OPENSSL_cleanse(username.data(), username.size());
            username.clear();
            OPENSSL_cleanse(password.data(), password.size());
            password.clear();
            OPENSSL_cleanse(totp.data(), totp.size());
            totp.clear();
        } else if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            std::string title;
            std::string firstName;
            std::string middleName;
            std::string lastName;
            std::string username;
            std::string company;
            std::string nationalInsuranceNum;
            std::string passportNum;
            std::string licenceNum;
            std::string email;
            std::string phone;
            std::string address1;
            std::string address2;
            std::string address3;
            std::string city;
            std::string county;
            std::string postalCode;
            std::string country;

            identityItem.GetTitle(title)
                        .GetFirstName(firstName)
                        .GetMiddleName(middleName)
                        .GetLastName(lastName)
                        .GetUsername(username)
                        .GetCompany(company)
                        .GetSSN(nationalInsuranceNum)
                        .GetPassportNumber(passportNum)
                        .GetLicenceNumber(licenceNum)
                        .GetEmail(email)
                        .GetPhone(phone)
                        .GetAddress1(address1)
                        .GetAddress2(address2)
                        .GetAddress3(address3)
                        .GetCity(city)
                        .GetState(county)
                        .GetPostalCode(postalCode)
                        .GetCountry(country)
                        .GetNotes(notes)
                        .GetFields(fields)
                        .GetFavorite(fav)
                        .GetAttachmentIDs(attachIds);
            
            for (auto& attach : attachIds) {
                std::string attname;

                identityItem.GetAttachmentName(attach, attname);

                WindowsUI::AttachmentEditField attField;
                attField.Title(winrt::to_hstring(attname));
                attField.Value(winrt::to_hstring(attach));
                attField.Bin([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                    auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                    auto id = winrt::to_string(field.Value());

                    ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                    ClientWarden::Vault::IdentityItem identityItem(vault, winrt::to_string(SidebarId().Text()));
                    
                    identityItem.RemoveAttachment(id)
                                .Close();
                    
                    co_return;
                });

                OPENSSL_cleanse(attname.data(), attname.size());
                attname.clear();

                SidebarAttachments().Children().Append(attField);
            }

            identityItem.Close();
            
            WindowsUI::GenericEditField titleField;
            titleField.Title(L"Title");
            titleField.Value(winrt::to_hstring(title));

            SidebarCard().Children().Append(titleField);
            
            WindowsUI::GenericEditField firstNameField;
            firstNameField.Title(L"First Name");
            firstNameField.Value(winrt::to_hstring(firstName));

            SidebarCard().Children().Append(firstNameField);
            
            WindowsUI::GenericEditField middleNameField;
            middleNameField.Title(L"Middle Name");
            middleNameField.Value(winrt::to_hstring(middleName));

            SidebarCard().Children().Append(middleNameField);
            
            WindowsUI::GenericEditField lastNameField;
            lastNameField.Title(L"Last Name");
            lastNameField.Value(winrt::to_hstring(lastName));

            SidebarCard().Children().Append(lastNameField);

            WindowsUI::GenericEditField usernameField;
            usernameField.Title(L"Username");
            usernameField.Value(winrt::to_hstring(username));

            SidebarCard().Children().Append(usernameField);

            WindowsUI::GenericEditField companyField;
            companyField.Title(L"Company");
            companyField.Value(winrt::to_hstring(company));

            SidebarCard().Children().Append(companyField);

            WindowsUI::PasswordEditField natInsNumField;
            natInsNumField.Title(L"National Insurance Number");
            natInsNumField.Value(winrt::to_hstring(nationalInsuranceNum));
            natInsNumField.DisablePasswordGen();

            SidebarCard().Children().Append(natInsNumField);

            WindowsUI::PasswordEditField passportField;
            passportField.Title(L"Passport Number");
            passportField.Value(winrt::to_hstring(passportNum));
            passportField.DisablePasswordGen();

            SidebarCard().Children().Append(passportField);

            WindowsUI::GenericEditField licenceField;
            licenceField.Title(L"Licence Number");
            licenceField.Value(winrt::to_hstring(licenceNum));

            SidebarCard().Children().Append(licenceField);

            WindowsUI::GenericEditField emailField;
            emailField.Title(L"Email");
            emailField.Value(winrt::to_hstring(email));

            SidebarCard().Children().Append(emailField);

            WindowsUI::GenericEditField phoneField;
            phoneField.Title(L"Phone");
            phoneField.Value(winrt::to_hstring(phone));

            SidebarCard().Children().Append(phoneField);
            
            WindowsUI::GenericEditField address1Block;
            address1Block.Title(L"Address 1");
            address1Block.Value(winrt::to_hstring(address1));

            SidebarCard().Children().Append(address1Block);
            
            WindowsUI::GenericEditField address2Block;
            address2Block.Title(L"Address 2");
            address2Block.Value(winrt::to_hstring(address2));

            SidebarCard().Children().Append(address2Block);
            
            WindowsUI::GenericEditField address3Block;
            address3Block.Title(L"Address 3");
            address3Block.Value(winrt::to_hstring(address3));

            SidebarCard().Children().Append(address3Block);
            
            WindowsUI::GenericEditField cityBlock;
            cityBlock.Title(L"City");
            cityBlock.Value(winrt::to_hstring(city));

            SidebarCard().Children().Append(cityBlock);
            
            WindowsUI::GenericEditField countyBlock;
            countyBlock.Title(L"State");
            countyBlock.Value(winrt::to_hstring(county));

            SidebarCard().Children().Append(countyBlock);
            
            WindowsUI::GenericEditField postalCodeBlock;
            postalCodeBlock.Title(L"Postal Code");
            postalCodeBlock.Value(winrt::to_hstring(postalCode));

            SidebarCard().Children().Append(postalCodeBlock);
            
            WindowsUI::GenericEditField countryBlock;
            countryBlock.Title(L"Country");
            countryBlock.Value(winrt::to_hstring(country));

            SidebarCard().Children().Append(countryBlock);

            OPENSSL_cleanse(title.data(), title.size());
            title.clear();
            OPENSSL_cleanse(firstName.data(), firstName.size());
            firstName.clear();
            OPENSSL_cleanse(middleName.data(), middleName.size());
            middleName.clear();
            OPENSSL_cleanse(lastName.data(), lastName.size());
            lastName.clear();
            OPENSSL_cleanse(username.data(), username.size());
            username.clear();
            OPENSSL_cleanse(company.data(), company.size());
            company.clear();
            OPENSSL_cleanse(nationalInsuranceNum.data(), nationalInsuranceNum.size());
            nationalInsuranceNum.clear();
            OPENSSL_cleanse(passportNum.data(), passportNum.size());
            passportNum.clear();
            OPENSSL_cleanse(licenceNum.data(), licenceNum.size());
            licenceNum.clear();
            OPENSSL_cleanse(email.data(), email.size());
            email.clear();
            OPENSSL_cleanse(phone.data(), phone.size());
            phone.clear();
            OPENSSL_cleanse(address1.data(), address1.size());
            address1.clear();
            OPENSSL_cleanse(address2.data(), address2.size());
            address2.clear();
            OPENSSL_cleanse(address3.data(), address3.size());
            address3.clear();
            OPENSSL_cleanse(city.data(), city.size());
            city.clear();
            OPENSSL_cleanse(county.data(), county.size());
            county.clear();
            OPENSSL_cleanse(postalCode.data(), postalCode.size());
            postalCode.clear();
            OPENSSL_cleanse(country.data(), country.size());
            country.clear();
        } else if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            std::string cardholderName;
            std::string number;
            std::string expirationMonth;
            std::string expirationYear;
            std::string cvv;
            std::string brand;

            cardItem.GetCardholderName(cardholderName)
                    .GetNumber(number)
                    .GetExpMonth(expirationMonth)
                    .GetExpYear(expirationYear)
                    .GetCode(cvv)
                    .GetBrand(brand)
                    .GetNotes(notes)
                    .GetFields(fields)
                    .GetFavorite(fav)
                    .GetAttachmentIDs(attachIds);
            
            for (auto& attach : attachIds) {
                std::string attname;

                cardItem.GetAttachmentName(attach, attname);

                WindowsUI::AttachmentEditField attField;
                attField.Title(winrt::to_hstring(attname));
                attField.Value(winrt::to_hstring(attach));
                attField.Bin([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                    auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                    auto id = winrt::to_string(field.Value());

                    ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                    ClientWarden::Vault::CardItem cardItem(vault, winrt::to_string(SidebarId().Text()));
                    
                    cardItem.RemoveAttachment(id)
                            .Close();
                    
                    co_return;
                });

                OPENSSL_cleanse(attname.data(), attname.size());
                attname.clear();

                SidebarAttachments().Children().Append(attField);
            }

            cardItem.Close();
            
            WindowsUI::GenericEditField cardholderNameField;
            cardholderNameField.Title(L"Cardholder Name");
            cardholderNameField.Value(winrt::to_hstring(cardholderName));

            SidebarCard().Children().Append(cardholderNameField);

            WindowsUI::PasswordEditField numberField;
            numberField.Title(L"Number");
            numberField.Value(winrt::to_hstring(number));
            numberField.DisablePasswordGen();

            SidebarCard().Children().Append(numberField);

            WindowsUI::GenericEditField brandField;
            brandField.Title(L"Brand");
            brandField.Value(winrt::to_hstring(brand));

            SidebarCard().Children().Append(brandField);
            
            WindowsUI::GenericEditField expirationMonField;
            expirationMonField.Title(L"Expiration Month");
            expirationMonField.Value(winrt::to_hstring(expirationMonth));

            SidebarCard().Children().Append(expirationMonField);
            
            WindowsUI::GenericEditField expirationYearField;
            expirationYearField.Title(L"Expiration Year");
            expirationYearField.Value(winrt::to_hstring(expirationYear));

            SidebarCard().Children().Append(expirationYearField);
            
            WindowsUI::PasswordEditField cvvField;
            cvvField.Title(L"CVV");
            cvvField.Value(winrt::to_hstring(cvv));
            cvvField.DisablePasswordGen();

            SidebarCard().Children().Append(cvvField);

            OPENSSL_cleanse(cardholderName.data(), cardholderName.size());
            cardholderName.clear();
            OPENSSL_cleanse(number.data(), number.size());
            number.clear();
            OPENSSL_cleanse(expirationMonth.data(), expirationMonth.size());
            expirationMonth.clear();
            OPENSSL_cleanse(expirationYear.data(), expirationYear.size());
            expirationYear.clear();
            OPENSSL_cleanse(cvv.data(), cvv.size());
            cvv.clear();
            OPENSSL_cleanse(brand.data(), brand.size());
            brand.clear();
        } else if (type == "Note") {
            ClientWarden::Vault::NoteItem noteItem(vault, id);

            noteItem.GetNotes(notes)
                    .GetFields(fields)
                    .GetFavorite(fav)
                    .GetAttachmentIDs(attachIds);
            
            for (auto& attach : attachIds) {
                std::string attname;

                noteItem.GetAttachmentName(attach, attname);

                WindowsUI::AttachmentEditField attField;
                attField.Title(winrt::to_hstring(attname));
                attField.Value(winrt::to_hstring(attach));
                attField.Bin([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                    auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                    auto id = winrt::to_string(field.Value());

                    ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                    ClientWarden::Vault::NoteItem noteItem(vault, winrt::to_string(SidebarId().Text()));
                    
                    noteItem.RemoveAttachment(id)
                            .Close();
                    
                    co_return;
                });

                OPENSSL_cleanse(attname.data(), attname.size());
                attname.clear();

                SidebarAttachments().Children().Append(attField);
            }

            noteItem.Close();
        } else if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            std::string privKey;
            std::string pubKey;
            std::string fingerprint;

            sshkeyItem.GetPrivateKey(privKey)
                      .GetPublicKey(pubKey)
                      .GetFingerprint(fingerprint)
                      .GetNotes(notes)
                      .GetFields(fields)
                      .GetFavorite(fav)
                      .GetAttachmentIDs(attachIds);
            
            for (auto& attach : attachIds) {
                std::string attname;

                sshkeyItem.GetAttachmentName(attach, attname);

                WindowsUI::AttachmentEditField attField;
                attField.Title(winrt::to_hstring(attname));
                attField.Value(winrt::to_hstring(attach));
                attField.Bin([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                    auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                    auto id = winrt::to_string(field.Value());

                    ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                    ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, winrt::to_string(SidebarId().Text()));
                    
                    sshkeyItem.RemoveAttachment(id)
                              .Close();
                    
                    co_return;
                });

                OPENSSL_cleanse(attname.data(), attname.size());
                attname.clear();

                SidebarAttachments().Children().Append(attField);
            }

            sshkeyItem.Close();
            
            WindowsUI::PasswordEditField privField;
            privField.Title(L"Private Key");
            privField.Value(winrt::to_hstring(privKey));
            privField.DisablePasswordGen();

            SidebarCard().Children().Append(privField);
            
            WindowsUI::GenericEditField publicField;
            publicField.Title(L"Public Key");
            publicField.Value(winrt::to_hstring(pubKey));

            SidebarCard().Children().Append(publicField);
            
            WindowsUI::GenericEditField fingerField;
            fingerField.Title(L"Fingerprint");
            fingerField.Value(winrt::to_hstring(fingerprint));

            SidebarCard().Children().Append(fingerField);

            OPENSSL_cleanse(privKey.data(), privKey.size());
            privKey.clear();
            OPENSSL_cleanse(pubKey.data(), pubKey.size());
            pubKey.clear();
            OPENSSL_cleanse(fingerprint.data(), fingerprint.size());
            fingerprint.clear();
        }

        SidebarNotes().Text(winrt::to_hstring(notes));

        OPENSSL_cleanse(notes.data(), notes.size());
        notes.clear();

        if (fav) {
            SidebarFav().UriSource(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_star_24_filled.png"));
        } else {
            SidebarFav().UriSource(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_star_24_regular.png"));
        }

        fav = false;

        for (auto& [FieldType, name, value] : fields) {
            if (FieldType == ClientWarden::Vault::CustomFieldType::Text) {
                WindowsUI::TextEditField texField;
                texField.Title(winrt::to_hstring(name));
                texField.Value(winrt::to_hstring(value));
                texField.DeleteField([this, texField](auto, auto) {
                    auto parent = SidebarFields();
                    uint32_t index;
                    parent.Children().IndexOf(texField, index);
                    parent.Children().RemoveAt(index);
                });
                SidebarFields().Children().Append(texField);
            } else if (FieldType == ClientWarden::Vault::CustomFieldType::Hidden) {
                WindowsUI::HiddenEditField hidField;
                hidField.Title(winrt::to_hstring(name));
                hidField.Value(winrt::to_hstring(value));
                hidField.DeleteField([this, hidField](auto, auto) {
                    auto parent = SidebarFields();
                    uint32_t index;
                    parent.Children().IndexOf(hidField, index);
                    parent.Children().RemoveAt(index);
                });
                SidebarFields().Children().Append(hidField);
            } else if (FieldType == ClientWarden::Vault::CustomFieldType::Checkbox) {
                WindowsUI::CheckboxEditField checkField;
                checkField.Title(winrt::to_hstring(name));
                if (value == "true") {
                    checkField.Value(true);
                } else {
                    checkField.Value(false);
                }
                checkField.DeleteField([this, checkField](auto, auto) {
                    auto parent = SidebarFields();
                    uint32_t index;
                    parent.Children().IndexOf(checkField, index);
                    parent.Children().RemoveAt(index);
                });
                SidebarFields().Children().Append(checkField);
            } else if (FieldType == ClientWarden::Vault::CustomFieldType::Linked) {
                WindowsUI::LinkedEditField linkedField;
                linkedField.Title(winrt::to_hstring(name));
                if (type == "Login") {
                    linkedField.AddOption(L"Username");
                    linkedField.AddOption(L"Password");
                }
                if (value == "100") {
                    linkedField.Value(L"Username");
                } else if (value == "101") {
                    linkedField.Value(L"Password");
                }
                linkedField.DeleteField([this, linkedField](auto, auto) {
                    auto parent = SidebarFields();
                    uint32_t index;
                    parent.Children().IndexOf(linkedField, index);
                    parent.Children().RemoveAt(index);
                });
                SidebarFields().Children().Append(linkedField);
            }
            OPENSSL_cleanse(name.data(), name.size());
            name.clear();
            OPENSSL_cleanse(value.data(), value.size());
            value.clear();
        }
    }

    void VaultUI::StartTOTPThread() {
        auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
        mt_running = true;
        mt_thread = std::thread([this, dispatcher]() {
            GUID guid{};
            ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

            while (mt_running)
            {
                auto nextTick = std::chrono::steady_clock::now() + std::chrono::seconds(1);

                dispatcher.TryEnqueue([this, &vault, &guid]()
                {
                    auto text = SidebarId().Text();

                    if (!text.empty() && text.size() == 36) {
                        auto type = SidebarType().Text();
                        if (!text.empty() && type == L"Login") {
                            TOTPField field = nullptr;
                            for (auto child : SidebarCard().Children()) {
                                field = child.try_as<TOTPField>();
                                if (field) {
                                    break;
                                }
                            }
                            if (field) {
                                ClientWarden::Vault::LoginItem loginItem(vault, winrt::to_string(text));

                                /*
                                 * SECRET DATA
                                */
                                ClientWarden::Vault::TOTPCode code;
                                code.code = "";

                                loginItem.GetTotp(code)
                                        .Close();
                                
                                if (code.code != "") {
                                    int secs = static_cast<int>(code.remaining - std::time(nullptr));
                                    field.Value(winrt::to_hstring(code.code));
                                    field.Time(secs);
                                }
                                OPENSSL_cleanse(code.code.data(), code.code.size());
                                code.code.clear();
                            }
                        }
                    }
                });

                std::this_thread::sleep_until(nextTick);
            }
        });
    }

    void VaultUI::StopTOTPThread() {
        mt_running = false;
        if (mt_thread.joinable()) {
            mt_thread.join();
        }
    }

    

    void VaultUI::VaultItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        if (isEdit) {
            SidebarViewMode();
        }
        auto item = sender.as<WindowsUI::VaultItem>();
    
        winrt::hstring id = item.itemID();
        winrt::hstring title = item.Title();
        winrt::hstring type = item.itemType();
        winrt::Microsoft::UI::Xaml::Media::ImageSource logo = item.Logo();

        PopulateSidePane(id, title, type, logo);
    }
    
    void VaultUI::Favorite_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        bool fav = false;

        auto field = sender.as<winrt::Microsoft::UI::Xaml::Controls::BitmapIcon>();
        if (field.UriSource().RawUri() == L"ms-appx:///Assets/ic_fluent_star_24_regular.png") {
            fav = true;
            field.UriSource(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_star_24_filled.png"));
        } else {
            fav = false;
            field.UriSource(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_star_24_regular.png"));
        }

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            loginItem.SetFavorite(fav)
                     .Commit();
        } else if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            identityItem.SetFavorite(fav)
                        .Commit();
        } else if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            cardItem.SetFavorite(fav)
                    .Commit();
        } else if (type == "Note") {
            ClientWarden::Vault::NoteItem noteItem(vault, id);

            noteItem.SetFavorite(fav)
                    .Commit();
        } else if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            sshkeyItem.SetFavorite(fav)
                      .Commit();
        }
    }
    
    void VaultUI::Delete_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            loginItem.Bin();
        } else if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            identityItem.Bin();
        } else if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            cardItem.Bin();
        } else if (type == "Note") {
            ClientWarden::Vault::NoteItem noteItem(vault, id);

            noteItem.Bin();
        } else if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            sshkeyItem.Bin();
        }

        auto items = VaultItemList().Children();
        for (uint32_t i = 0; i < items.Size(); i++) {
            if (auto item = items.GetAt(i).try_as<winrt::WindowsUI::VaultItem>()) {
                if (winrt::to_string(item.itemID()) == id) {
                    items.RemoveAt(i);
                    break;
                }
            }
        }
    }

    void VaultUI::Perm_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            loginItem.Delete();
        } else if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            identityItem.Delete();
        } else if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            cardItem.Delete();
        } else if (type == "Note") {
            ClientWarden::Vault::NoteItem noteItem(vault, id);

            noteItem.Delete();
        } else if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            sshkeyItem.Delete();
        }

        auto items = VaultItemList().Children();
        for (uint32_t i = 0; i < items.Size(); i++) {
            if (auto item = items.GetAt(i).try_as<winrt::WindowsUI::VaultItem>()) {
                if (winrt::to_string(item.itemID()) == id) {
                    items.RemoveAt(i);
                    break;
                }
            }
        }
    }

    void VaultUI::Restore_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            loginItem.UnBin();
        } else if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            identityItem.UnBin();
        } else if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            cardItem.UnBin();
        } else if (type == "Note") {
            ClientWarden::Vault::NoteItem noteItem(vault, id);

            noteItem.UnBin();
        } else if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            sshkeyItem.UnBin();
        }

        auto items = VaultItemList().Children();
        for (uint32_t i = 0; i < items.Size(); i++) {
            if (auto item = items.GetAt(i).try_as<winrt::WindowsUI::VaultItem>()) {
                if (winrt::to_string(item.itemID()) == id) {
                    items.RemoveAt(i);
                    break;
                }
            }
        }
    }

    void VaultUI::Duplicate_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            std::string dupid;

            loginItem.Duplicate(dupid)
                     .Close();

            ClientWarden::Vault::LoginItem duploginItem(vault, dupid);

            /*
             * SECRET DATA
            */
            std::string loginName;
            std::string loginUser;
            std::vector<std::string> loginUrl;

            duploginItem.GetName(loginName)
                        .GetUsername(loginUser)
                        .GetWebsites(loginUrl)
                        .Close();

            std::string lgurl = "ms-appx:///Assets/ic_fluent_globe_24_filled.png";
                
            if (loginUrl.size() != 0) {
                lgurl = vault.downloadIcon(loginUrl[0]);
            }

            if (lgurl == "") {
                lgurl = "ms-appx:///Assets/ic_fluent_globe_24_filled.png";
            }

            /*
             * SECRET DATA
            */
            winrt::hstring hloginName = winrt::to_hstring(loginName);
            winrt::hstring hloginUser = winrt::to_hstring(loginUser);
               
            OPENSSL_cleanse(loginName.data(), loginName.size());
            loginName.clear();
            OPENSSL_cleanse(loginUser.data(), loginUser.size());
            loginUser.clear();
               
            for (auto& uri : loginUrl) {
                OPENSSL_cleanse(uri.data(), uri.size());
                uri.clear();
            }
            loginUrl.clear();

            WindowsUI::VaultItem item;
            item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(winrt::to_hstring(lgurl))));
            item.Title(hloginName);
            item.Detail(hloginUser);
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(dupid));
            item.itemType(L"Login");

            VaultItemList().Children().Append(item);
        } else if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            std::string dupid;

            cardItem.Duplicate(dupid)
                    .Close();
            
            ClientWarden::Vault::CardItem dupcardItem(vault, dupid);

            /*
             * SECRET DATA
            */
            std::string cardName;
            std::string cardnam;
            std::string cardBrand;

            dupcardItem.GetName(cardName)
                       .GetCardholderName(cardnam)
                       .GetBrand(cardBrand)
                       .Close();
               
            auto hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_credit_card_person_24_regular.png"));
            if (cardBrand == "Amex") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-amex-brands-solid.png"));
            } else if (cardBrand == "Visa") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-visa-brands-solid.png"));
            } else if (cardBrand == "Mastercard") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-mastercard-brands-solid.png"));
            } else if (cardBrand == "Discover") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-discover-brands-solid.png"));
            } else if (cardBrand == "Diners Club") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-diners-club-brands-solid.png"));
            } else if (cardBrand == "JCB") {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/cc-jcb-brands-solid.png"));
            } else {
                hlogo = winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_credit_card_person_24_regular.png"));
            }

            /*
             * SECRET DATA
            */
            winrt::hstring hcardName = winrt::to_hstring(cardName);
            winrt::hstring hcardnam = winrt::to_hstring(cardnam);
                
            OPENSSL_cleanse(cardName.data(), cardName.size());
            cardName.clear();
            OPENSSL_cleanse(cardnam.data(), cardnam.size());
            cardnam.clear();
            OPENSSL_cleanse(cardBrand.data(), cardBrand.size());
            cardBrand.clear();

            WindowsUI::VaultItem item;
            item.Logo(hlogo);
            item.Title(hcardName);
            item.Detail(hcardnam);
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(dupid));
            item.itemType(L"Card");

            VaultItemList().Children().Append(item);
        } else if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            std::string dupid;

            identityItem.Duplicate(dupid)
                        .Close();
            
            ClientWarden::Vault::IdentityItem dupidentityItem(vault, dupid);

            /*
             * SECRET DATA
            */
            std::string identityName;
            std::string identityDetail;

            dupidentityItem.GetName(identityName)
                           .GetFirstName(identityDetail)
                           .Close();

            /*
             * SECRET DATA
            */
            winrt::hstring hidentityName = winrt::to_hstring(identityName);
            winrt::hstring hidentityDetail = winrt::to_hstring(identityDetail);
                
            OPENSSL_cleanse(identityName.data(), identityName.size());
            identityName.clear();
            OPENSSL_cleanse(identityDetail.data(), identityDetail.size());
            identityDetail.clear();

            WindowsUI::VaultItem item;
            item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_share_screen_person_24_regular.png")));
            item.Title(hidentityName);
            item.Detail(hidentityDetail);
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(dupid));
            item.itemType(L"Identity");

            VaultItemList().Children().Append(item);
        } else if (type == "Note") {
            ClientWarden::Vault::NoteItem noteItem(vault, id);

            std::string dupid;

            noteItem.Duplicate(dupid)
                    .Close();
            
            ClientWarden::Vault::NoteItem dupnoteItem(vault, dupid);

            /*
             * SECRET DATA
            */
            std::string noteName;

            dupnoteItem.GetName(noteName)
                       .Close();

            /*
             * SECRET DATA
            */
            winrt::hstring hnoteName = winrt::to_hstring(noteName);
                
            OPENSSL_cleanse(noteName.data(), noteName.size());
            noteName.clear();

            WindowsUI::VaultItem item;
            item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_note_24_regular.png")));
            item.Title(hnoteName);
            item.Detail(L"");
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(dupid));
            item.itemType(L"Note");

            VaultItemList().Children().Append(item);
        } else if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshItem(vault, id);

            std::string dupid;

            sshItem.Duplicate(dupid)
                   .Close();
            
            ClientWarden::Vault::SSHKeyItem dupsshItem(vault, dupid);

            /*
             * SECRET DATA
            */
            std::string sshName;
            std::string sshDetail;

            dupsshItem.GetName(sshName)
                      .GetFingerprint(sshDetail)
                      .Close();

            /*
             * SECRET DATA
            */
            winrt::hstring hsshName = winrt::to_hstring(sshName);
            winrt::hstring hsshDetail = winrt::to_hstring(sshDetail);
             
            OPENSSL_cleanse(sshName.data(), sshName.size());
            sshName.clear();
            OPENSSL_cleanse(sshDetail.data(), sshDetail.size());
            sshDetail.clear();

            WindowsUI::VaultItem item;
            item.Logo(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_key_24_regular.png")));
            item.Title(hsshName);
            item.Detail(hsshDetail);
            item.Click({ this, &VaultUI::VaultItem_Click });
            item.itemID(winrt::to_hstring(dupid));
            item.itemType(L"SSHKey");

            VaultItemList().Children().Append(item);
        }
    }

    void VaultUI::PrivSSHItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        auto field = sender.as<WindowsUI::PasswordField>();
        std::string uri = winrt::to_string(field.GetShowHideImage().UriSource().RawUri());

        if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string password;

            sshkeyItem.GetPrivateKey(password)
                      .Close();

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
        }
    }
    
    void VaultUI::NumberCardItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        auto field = sender.as<WindowsUI::PasswordField>();
        std::string uri = winrt::to_string(field.GetShowHideImage().UriSource().RawUri());

        if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string password;

            cardItem.GetNumber(password)
                    .Close();

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
        }
    }

    void VaultUI::CVVCardItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        auto field = sender.as<WindowsUI::PasswordField>();
        std::string uri = winrt::to_string(field.GetShowHideImage().UriSource().RawUri());

        if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string password;

            cardItem.GetCode(password)
                    .Close();

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
        }
    }
    
    void VaultUI::NatIncIdentityItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        auto field = sender.as<WindowsUI::PasswordField>();
        std::string uri = winrt::to_string(field.GetShowHideImage().UriSource().RawUri());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string password;

            identityItem.GetSSN(password)
                        .Close();

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
        }
    }
    
    void VaultUI::PassportIdentityItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        auto field = sender.as<WindowsUI::PasswordField>();
        std::string uri = winrt::to_string(field.GetShowHideImage().UriSource().RawUri());

        if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            /*
             * SECRET DATA
            */
            std::string password;

            identityItem.GetPassportNumber(password)
                        .Close();

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
        }
    }

    void VaultUI::HiddenItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

        std::string id = winrt::to_string(SidebarId().Text());
        std::string type = winrt::to_string(SidebarType().Text());

        auto HidField = sender.as<WindowsUI::HiddenField>();
        std::string uri = winrt::to_string(HidField.GetShowHideImage().UriSource().RawUri());

        /*
         * SECRET DATA
        */
        std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> fields;

        if (type == "Login") {
            ClientWarden::Vault::LoginItem loginItem(vault, id);

            loginItem.GetFields(fields)
                     .Close();
        } else if (type == "Card") {
            ClientWarden::Vault::CardItem cardItem(vault, id);

            cardItem.GetFields(fields)
                    .Close();
        } else if (type == "Identity") {
            ClientWarden::Vault::IdentityItem identityItem(vault, id);

            identityItem.GetFields(fields)
                        .Close();
        } else if (type == "Note") {
            ClientWarden::Vault::NoteItem noteItem(vault, id);

            noteItem.GetFields(fields)
                    .Close();
        } else if (type == "SSHKey") {
            ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

            sshkeyItem.GetFields(fields)
                      .Close();
        }

        for (auto& [type, name, value] : fields) {
            if (name == winrt::to_string(HidField.Title())) {
                if (uri == "ms-appx:///Assets/ic_fluent_eye_show_24_regular.png") {
                    int siz = value.size();

                    std::string hidPass;
                    
                    for (int i = 0; i < siz; i++) {
                        hidPass = hidPass + "•";
                    }

                    HidField.Value(winrt::to_hstring(hidPass));
                } else {
                    HidField.Value(winrt::to_hstring(value));
                }
            }
            OPENSSL_cleanse(name.data(), name.size());
            name.clear();
            OPENSSL_cleanse(value.data(), value.size());
            value.clear();
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

            /*
             * SECRET DATA
            */
            std::string password;

            loginItem.GetPassword(password)
                     .Close();

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
        }
    }
}
