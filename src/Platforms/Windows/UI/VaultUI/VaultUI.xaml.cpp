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
        try {
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
        } catch (const std::exception& e) {
            logger->error("NavigationView_Loaded ~ exception: {}", e.what());
        } catch (...) {
            logger->error("NavigationView_Loaded ~ exception");
        }
    }

    void VaultUI::NewItemDropdown_SelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& e) {
        try {
            auto box = sender.as<winrt::Microsoft::UI::Xaml::Controls::ComboBox>();
            auto selected = box.SelectedItem().as<winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem>();
            std::string value = winrt::to_string(selected.Content().as<winrt::hstring>());

            std::string type = winrt::to_string(SidebarType().Text());

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
            
            SidebarEdit_Click(winrt::box_value(winrt::hstring{}), winrt::Microsoft::UI::Xaml::RoutedEventArgs{});
        } catch (const std::exception& e) {
            logger->error("NavigationView_Loaded ~ exception: {}", e.what());
        } catch (...) {
            logger->error("NavigationView_Loaded ~ exception");
        }
    }

    void VaultUI::NavigationView_SelectionChanged(winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender, winrt::Microsoft::UI::Xaml::Controls::NavigationViewSelectionChangedEventArgs const& args) {
        try {
            auto selectedItem = args.SelectedItem().try_as<winrt::Microsoft::UI::Xaml::Controls::NavigationViewItem>();

            if (!selectedItem) {
                return;
            }

            SidebarEmptyMode();

            std::string tag = winrt::to_string(selectedItem.Name());

            ClientWarden::Vault::CipherQuery query(vault);

            query.FilterNameByRegex(winrt::to_string(SearchBar().Text()));

            std::vector<std::pair<ClientWarden::Vault::CipherType, std::string>> cipherIDs;

            PermButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            RestoreButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            DeleteButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);

            if (tag != "NewFold") {
                SettingsPanel().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
                MainGrid().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            }

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
                SettingsPanel().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
                MainGrid().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            } else {
                cipherIDs = query.FilterByUnbinned()
                                .FilterByFolder(tag)
                                .GetCiphers();
            }

            VaultItemList().Children().Clear();

            PopulateItemsList(cipherIDs);
        } catch (const std::exception& e) {
            logger->error("NavigationView_SelectionChanged ~ exception: {}", e.what());
        } catch (...) {
            logger->error("NavigationView_SelectionChanged ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::Attachment_Download(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            winrt::apartment_context ui_thread;

            auto field = sender.as<winrt::WindowsUI::AttachmentField>();
            auto id = winrt::to_string(field.Value());
            auto sidebarid = winrt::to_string(SidebarId().Text());

            field.Progress(0.01);

            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();

            co_await winrt::resume_background();

            ClientWarden::Vault::GenericItem genericItem(vault, sidebarid);

            std::string attCont;

            genericItem.GetAttachment(id, attCont,
                [field, dispatcher](float progress) {
                    dispatcher.TryEnqueue([field, progress]() {
                        field.Progress(progress);
                    });
                })
                .Close();
                    
            co_await ui_thread;

            field.Progress(1.0);

            if (attCont == "") {
                field.Progress(0.0);
                OPENSSL_cleanse(attCont.data(), attCont.size());
                co_return;
            }
                        
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
        } catch (const std::exception& e) {
            logger->error("Attachment_Download ~ exception: {}", e.what());
        } catch (...) {
            logger->error("Attachment_Download ~ exception");
        }
    }

    void VaultUI::SearchBox_TextChanged(winrt::Microsoft::UI::Xaml::Controls::AutoSuggestBox const& sender, winrt::Microsoft::UI::Xaml::Controls::AutoSuggestBoxTextChangedEventArgs const& args) {
        try {
            auto selectedItem = NavView().SelectedItem().try_as<winrt::Microsoft::UI::Xaml::Controls::NavigationViewItem>();

            if (!selectedItem) {
                return;
            }

            std::string tag = winrt::to_string(selectedItem.Name());

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
        } catch (const std::exception& e) {
            logger->error("SearchBox_TextChanged ~ exception: {}", e.what());
        } catch (...) {
            logger->error("SearchBox_TextChanged ~ exception");
        }
    }

    void VaultUI::PopulateItem(std::pair<ClientWarden::Vault::CipherType, std::string> cipherId) {
        try {
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
        } catch (const std::exception& e) {
            logger->error("PopulateItem ~ exception: {}", e.what());
        } catch (...) {
            logger->error("PopulateItem ~ exception");
        }
    }

    void VaultUI::PopulateItemsList(std::vector<std::pair<ClientWarden::Vault::CipherType, std::string>> cipherIDs) {
        try {
            for (auto& cipher : cipherIDs) {
                PopulateItem(cipher);
            }
        } catch (const std::exception& e) {
            logger->error("PopulateItemsList ~ exception: {}", e.what());
        } catch (...) {
            logger->error("PopulateItemsList ~ exception");
        }
    }
    
    void VaultUI::FieldsDropdown_SelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& e) {
        try {
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
        } catch (const std::exception& e) {
            logger->error("FieldsDropdown_SelectionChanged ~ exception: {}", e.what());
        } catch (...) {
            logger->error("FieldsDropdown_SelectionChanged ~ exception");
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
        try {
            mt_running = false;
            if (mt_thread.joinable()) {
                mt_thread.join();
            }
        } catch (const std::exception& e) {
            logger->error("StopTOTPThread ~ exception: {}", e.what());
        } catch (...) {
            logger->error("StopTOTPThread ~ exception");
        }
    }

    void VaultUI::VaultItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            if (isEdit) {
                SidebarViewMode();
            }
            auto item = sender.as<WindowsUI::VaultItem>();
        
            winrt::hstring id = item.itemID();
            winrt::hstring title = item.Title();
            winrt::hstring type = item.itemType();
            winrt::Microsoft::UI::Xaml::Media::ImageSource logo = item.Logo();

            PopulateSidePane(id, title, type, logo);
        } catch (const std::exception& e) {
            logger->error("VaultItem_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("VaultItem_Click ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::SettingsTimeout_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        winrt::apartment_context ui_thread;
        try {

            vault.settingsData["clipboardClear"] = std::stoi(winrt::to_string(TimeoutBox().Text()));

            co_await winrt::resume_background();

            clipboard.SetDelay(vault.settingsData["clipboardClear"]);
            vault.storage.write("settings.json", vault.settingsData.dump(4));
            
            co_await ui_thread;
            co_return;
        } catch (const std::exception& e) {
            logger->error("VaultItem_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("VaultItem_Click ~ exception");
        }

        co_await ui_thread;

        TimeoutBox().Text(L"30");
        vault.settingsData["clipboardClear"] = 30;
        clipboard.SetDelay(30);
        vault.storage.write("settings.json", vault.settingsData.dump(4));
    }
}
