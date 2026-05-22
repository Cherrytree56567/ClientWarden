#include "pch.h"
#include "VaultUI.xaml.h"

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    void VaultUI::SidebarEditMode() {
        try {
            isEdit = true;
            SidebarTitle().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            SidebarTitleBox().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);

            SidebarTitleBox().Text(SidebarTitle().Text());

            SidebarNotesEdit().Text(SidebarNotes().Text());
            SidebarNotes().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            SidebarNotesEdit().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);

            EditButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            DuplicateButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            DeleteButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            SaveButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            CancelButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);

            AddButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
        } catch (const std::exception& e) {
            logger->error("SidebarEditMode ~ exception: {}", e.what());
        } catch (...) {
            logger->error("SidebarEditMode ~ exception");
        }
    }

    void VaultUI::SidebarViewMode() {
        try {
            isEdit = false;
            SidebarTitle().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            SidebarTitleBox().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);

            SidebarTitleBox().Text(SidebarTitle().Text());

            SidebarNotesEdit().Text(SidebarNotes().Text());
            SidebarNotes().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            SidebarNotesEdit().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);

            EditButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            DuplicateButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            DeleteButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Visible);
            SaveButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            CancelButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);

            AddButton().Visibility(winrt::Microsoft::UI::Xaml::Visibility::Collapsed);
            
            SelectItem().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
            SelectItemPath().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
        } catch (const std::exception& e) {
            logger->error("SidebarViewMode ~ exception: {}", e.what());
        } catch (...) {
            logger->error("SidebarViewMode ~ exception");
        }
    }

    void VaultUI::SidebarEmptyMode() {
        try {
            SelectItem().Visibility(Microsoft::UI::Xaml::Visibility::Collapsed);
            SelectItemPath().Visibility(Microsoft::UI::Xaml::Visibility::Visible);
        } catch (const std::exception& e) {
            logger->error("SidebarEmptyMode ~ exception: {}", e.what());
        } catch (...) {
            logger->error("SidebarEmptyMode ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::PopulateSidePane(winrt::hstring id, winrt::hstring title, winrt::hstring type, winrt::Microsoft::UI::Xaml::Media::ImageSource logo) {
        try {
            winrt::apartment_context ui_thread;

            SidebarViewMode();

            SidebarImage().Source(logo);
            SidebarTitle().Text(title);
            SidebarType().Text(type);
            SidebarId().Text(id);

            SidebarCard().Children().Clear();
            SidebarFields().Children().Clear();
            SidebarAttachments().Children().Clear();
            SidebarNotes().Text(L"");

            mt_folderPick = true;
            FolderPicker().GetComboBox().IsEnabled(false);
            FolderPicker().GetComboBox().Background(winrt::Microsoft::UI::Xaml::Media::SolidColorBrush(winrt::Microsoft::UI::Colors::Transparent()));
            FolderPicker().GetComboBox().BorderBrush(winrt::Microsoft::UI::Xaml::Media::SolidColorBrush(winrt::Microsoft::UI::Colors::Transparent()));
            mt_folderPick = false;

            /*
            * SECRET DATA
            */
            std::string notes = "";
            std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> fields;
            std::string folder = "";
            std::vector<std::string> attachIds;
            bool fav = false;
            
            if (type == L"Login") {
                ClientWarden::Vault::LoginItem loginItem(vault, winrt::to_string(id));

                /*
                * SECRET DATA
                */
                std::string username;
                std::string password;
                ClientWarden::Vault::TOTPCode totp;
                totp.code = "";

                std::vector<std::time_t> passkeyCreation;

                std::vector<std::string> websites;

                co_await winrt::resume_background();

                loginItem.GetUsername(username)
                         .GetPassword(password)
                         .GetTotp(totp)
                         .GetWebsites(websites)
                         .GetPasskeyCreationDate(passkeyCreation)
                         .GetNotes(notes)
                         .GetFields(fields)
                         .GetFavorite(fav)
                         .GetFolder(folder)
                         .GetAttachmentIDs(attachIds)
                         .Close();
                
                int siz = password.size();

                OPENSSL_cleanse(password.data(), password.size());
                password.clear();

                std::string hidPass;
                
                for (int i = 0; i < siz; i++) {
                    hidPass = hidPass + "•";
                }

                co_await ui_thread;
                
                WindowsUI::GenericField field;
                field.Title(L"Username");
                field.Value(winrt::to_hstring(username));
                field.Clipboard({ this, &VaultUI::Username_Copy });

                SidebarCard().Children().Append(field);
                
                WindowsUI::PasswordField passwdField;
                passwdField.Title(L"Password");
                passwdField.Value(winrt::to_hstring(hidPass));
                passwdField.ShowHide({ this, &VaultUI::LoginPasswordItem_Click });
                passwdField.Clipboard({ this, &VaultUI::Password_Copy });

                SidebarCard().Children().Append(passwdField);

                for (auto& passkCreation : passkeyCreation) {
                    struct tm tm_info;
                    errno_t err = localtime_s(&tm_info, &passkCreation);

                    if (err != 0) continue;
                        
                    char buffer[64];
                    strftime(buffer, sizeof(buffer), "Created %d/%m/%Y, %H:%M", &tm_info);

                    std::string passkeyCreationS = buffer;
                    WindowsUI::PasskeyField passkeyField;
                    passkeyField.Title(L"Passkey");
                    passkeyField.Value(winrt::to_hstring(passkeyCreationS));

                    SidebarCard().Children().Append(passkeyField);

                    memset(buffer, 0, sizeof(buffer));
                    OPENSSL_cleanse(passkeyCreationS.data(), passkeyCreationS.size());
                    passkeyCreationS.clear();
                }

                if (totp.code != "") {
                    WindowsUI::TOTPField totpField;
                    totpField.Title(L"One Time Password");
                    totpField.Value(winrt::to_hstring(hidPass));
                    totpField.Clipboard({ this, &VaultUI::TOTP_Copy });
                    
                    time_t now = std::time(nullptr);
                    double seconds = std::difftime(totp.remaining, now);

                    int secs = static_cast<int>(seconds) % 60;
                    totpField.Value(winrt::to_hstring(totp.code));
                    totpField.Time(secs);

                    SidebarCard().Children().Append(totpField);
                }

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

                co_await winrt::resume_background();

                OPENSSL_cleanse(username.data(), username.size());
                username.clear();
                OPENSSL_cleanse(totp.code.data(), totp.code.size());
                totp.code.clear();

                co_await ui_thread;
            } else if (type == L"Identity") {
                ClientWarden::Vault::IdentityItem identityItem(vault, winrt::to_string(id));

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

                co_await winrt::resume_background();

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
                            .GetFolder(folder)
                            .GetFields(fields)
                            .GetFavorite(fav)
                            .GetAttachmentIDs(attachIds)
                            .Close();

                co_await ui_thread;
                
                WindowsUI::GenericField nameField;
                nameField.Title(L"Name");
                nameField.Value(winrt::to_hstring(title + " " + firstName + " " + middleName + " " + lastName));
                nameField.Clipboard({ this, &VaultUI::NameIdentity_Copy });

                SidebarCard().Children().Append(nameField);

                WindowsUI::GenericField usernameField;
                usernameField.Title(L"Username");
                usernameField.Value(winrt::to_hstring(username));
                usernameField.Clipboard({ this, &VaultUI::UsernameIdentity_Copy });

                SidebarCard().Children().Append(usernameField);

                WindowsUI::GenericField companyField;
                companyField.Title(L"Company");
                companyField.Value(winrt::to_hstring(company));
                companyField.Clipboard({ this, &VaultUI::CompanyIdentity_Copy });

                SidebarCard().Children().Append(companyField);

                std::string hidNationalIden;
                
                for (int i = 0; i < nationalInsuranceNum.size(); i++) {
                    hidNationalIden = hidNationalIden + "•";
                }

                WindowsUI::PasswordField natInsNumField;
                natInsNumField.Title(L"National Insurance Number");
                natInsNumField.Value(winrt::to_hstring(hidNationalIden));
                natInsNumField.ShowHide({ this, &VaultUI::NatIncIdentityItem_Click });
                natInsNumField.Clipboard({ this, &VaultUI::NatInsIdentity_Copy });

                SidebarCard().Children().Append(natInsNumField);

                std::string hidpassportNum;
                
                for (int i = 0; i < passportNum.size(); i++) {
                    hidpassportNum = hidpassportNum + "•";
                }

                WindowsUI::PasswordField passportField;
                passportField.Title(L"Passport Number");
                passportField.Value(winrt::to_hstring(hidpassportNum));
                passportField.ShowHide({ this, &VaultUI::PassportIdentityItem_Click });
                passportField.Clipboard({ this, &VaultUI::PassportIdentity_Copy });

                SidebarCard().Children().Append(passportField);

                WindowsUI::GenericField licenceField;
                licenceField.Title(L"Licence Number");
                licenceField.Value(winrt::to_hstring(licenceNum));
                licenceField.Clipboard({ this, &VaultUI::LicenceIdentity_Copy });

                SidebarCard().Children().Append(licenceField);

                WindowsUI::GenericField emailField;
                emailField.Title(L"Email");
                emailField.Value(winrt::to_hstring(email));
                emailField.Clipboard({ this, &VaultUI::EmailIdentity_Copy });

                SidebarCard().Children().Append(emailField);

                WindowsUI::GenericField phoneField;
                phoneField.Title(L"Phone");
                phoneField.Value(winrt::to_hstring(phone));
                phoneField.Clipboard({ this, &VaultUI::PhoneIdentity_Copy });

                SidebarCard().Children().Append(phoneField);

                WindowsUI::WebsiteField addressField;
                addressField.Title(L"Address");
                
                winrt::Microsoft::UI::Xaml::Controls::TextBlock address1Block;
                address1Block.Text(winrt::to_hstring(address1));
                addressField.Value().Append(address1Block);
                
                winrt::Microsoft::UI::Xaml::Controls::TextBlock address2Block;
                address2Block.Text(winrt::to_hstring(address2));
                addressField.Value().Append(address2Block);
                
                winrt::Microsoft::UI::Xaml::Controls::TextBlock address3Block;
                address3Block.Text(winrt::to_hstring(address3));
                addressField.Value().Append(address3Block);
                
                winrt::Microsoft::UI::Xaml::Controls::TextBlock addrSubInfoBlock;
                addrSubInfoBlock.Text(winrt::to_hstring(city + ", " + county + ", " + postalCode));
                addressField.Value().Append(addrSubInfoBlock);
                
                winrt::Microsoft::UI::Xaml::Controls::TextBlock addrInfoBlock;
                addrInfoBlock.Text(winrt::to_hstring(country));
                addressField.Value().Append(addrInfoBlock);

                SidebarCard().Children().Append(addressField);

                co_await winrt::resume_background();

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

                co_await ui_thread;
            } else if (type == L"Card") {
                ClientWarden::Vault::CardItem cardItem(vault, winrt::to_string(id));

                std::string cardholderName;
                std::string number;
                std::string expirationMonth;
                std::string expirationYear;
                std::string cvv;
                std::string brand;

                co_await winrt::resume_background();

                cardItem.GetCardholderName(cardholderName)
                        .GetNumber(number)
                        .GetExpMonth(expirationMonth)
                        .GetExpYear(expirationYear)
                        .GetCode(cvv)
                        .GetBrand(brand)
                        .GetNotes(notes)
                        .GetFolder(folder)
                        .GetFields(fields)
                        .GetFavorite(fav)
                        .GetAttachmentIDs(attachIds)
                        .Close();

                co_await ui_thread;
                
                WindowsUI::GenericField cardholderNameField;
                cardholderNameField.Title(L"Cardholder Name");
                cardholderNameField.Value(winrt::to_hstring(cardholderName));
                cardholderNameField.Clipboard({ this, &VaultUI::CardholderCard_Copy });

                SidebarCard().Children().Append(cardholderNameField);

                std::string hidnum;
                
                for (int i = 0; i < number.size(); i++) {
                    hidnum = hidnum + "•";
                }
                
                WindowsUI::PasswordField numberField;
                numberField.Title(L"Number");
                numberField.Value(winrt::to_hstring(hidnum));
                numberField.ShowHide({ this, &VaultUI::NumberCardItem_Click });
                numberField.Clipboard({ this, &VaultUI::NumberCard_Copy });

                SidebarCard().Children().Append(numberField);
                
                WindowsUI::GenericField expirationField;
                expirationField.Title(L"Expiration");
                expirationField.Value(winrt::to_hstring(expirationMonth + " / " + expirationYear));
                expirationField.Clipboard({ this, &VaultUI::ExpirationCard_Copy });

                SidebarCard().Children().Append(expirationField);

                std::string hidcvv;
                
                for (int i = 0; i < cvv.size(); i++) {
                    hidcvv = hidcvv + "•";
                }
                
                WindowsUI::PasswordField cvvField;
                cvvField.Title(L"CVV");
                cvvField.Value(winrt::to_hstring(hidcvv));
                cvvField.ShowHide({ this, &VaultUI::CVVCardItem_Click });
                cvvField.Clipboard({ this, &VaultUI::CVVCard_Copy });

                SidebarCard().Children().Append(cvvField);

                co_await winrt::resume_background();

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

                co_await ui_thread;
            } else if (type == L"Note") {
                ClientWarden::Vault::NoteItem noteItem(vault, winrt::to_string(id));

                co_await winrt::resume_background();

                noteItem.GetNotes(notes)
                        .GetFolder(folder)
                        .GetFields(fields)
                        .GetFavorite(fav)
                        .GetAttachmentIDs(attachIds)
                        .Close();

                co_await ui_thread;
            } else if (type == L"SSHKey") {
                ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, winrt::to_string(id));

                std::string privKey;
                std::string pubKey;
                std::string fingerprint;

                co_await winrt::resume_background();

                sshkeyItem.GetPrivateKey(privKey)
                          .GetPublicKey(pubKey)
                          .GetFingerprint(fingerprint)
                          .GetNotes(notes)
                          .GetFolder(folder)
                          .GetFields(fields)
                          .GetFavorite(fav)
                          .GetAttachmentIDs(attachIds)
                          .Close();

                std::string hidnum;
                
                for (int i = 0; i < privKey.size(); i++) {
                    hidnum = hidnum + "•";
                }

                co_await ui_thread;
                
                WindowsUI::PasswordField privField;
                privField.Title(L"Private Key");
                privField.Value(winrt::to_hstring(hidnum));
                privField.ShowHide({ this, &VaultUI::PrivSSHItem_Click });
                privField.Clipboard({ this, &VaultUI::PrivSSH_Copy });

                SidebarCard().Children().Append(privField);
                
                WindowsUI::GenericField publicField;
                publicField.Title(L"Public Key");
                publicField.Value(winrt::to_hstring(pubKey));
                publicField.Clipboard({ this, &VaultUI::PubSSH_Copy });

                SidebarCard().Children().Append(publicField);
                
                WindowsUI::GenericField fingerField;
                fingerField.Title(L"Fingerprint");
                fingerField.Value(winrt::to_hstring(fingerprint));
                fingerField.Clipboard({ this, &VaultUI::FingSSH_Copy });

                SidebarCard().Children().Append(fingerField);

                co_await winrt::resume_background();

                OPENSSL_cleanse(privKey.data(), privKey.size());
                privKey.clear();
                OPENSSL_cleanse(pubKey.data(), pubKey.size());
                pubKey.clear();
                OPENSSL_cleanse(fingerprint.data(), fingerprint.size());
                fingerprint.clear();

                co_await ui_thread;
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
                    WindowsUI::TextField texField;
                    texField.Title(winrt::to_hstring(name));
                    texField.Value(winrt::to_hstring(value));
                    SidebarFields().Children().Append(texField);
                } else if (FieldType == ClientWarden::Vault::CustomFieldType::Hidden) {
                    WindowsUI::HiddenField hidField;
                    hidField.Title(winrt::to_hstring(name));

                    std::string hidite;
                    
                    for (int i = 0; i < value.size(); i++) {
                        hidite = hidite + "•";
                    }
                    hidField.Value(winrt::to_hstring(hidite));
                    hidField.ShowHide({ this, &VaultUI::HiddenItem_Click });
                    SidebarFields().Children().Append(hidField);
                } else if (FieldType == ClientWarden::Vault::CustomFieldType::Checkbox) {
                    WindowsUI::CheckboxField checkField;
                    checkField.Title(winrt::to_hstring(name));
                    if (value == "true") {
                        checkField.Value(true);
                    } else {
                        checkField.Value(false);
                    }
                    SidebarFields().Children().Append(checkField);
                } else if (FieldType == ClientWarden::Vault::CustomFieldType::Linked) {
                    WindowsUI::LinkedField linkedField;
                    linkedField.Title(winrt::to_hstring(name));
                    if (value == "100") {
                        linkedField.Value(L"Username");
                    } else if (value == "101") {
                        linkedField.Value(L"Password");
                    }
                    SidebarFields().Children().Append(linkedField);
                }
                OPENSSL_cleanse(name.data(), name.size());
                name.clear();
                OPENSSL_cleanse(value.data(), value.size());
                value.clear();
            }
            
            ClientWarden::Vault::GenericItem genericItem(vault, winrt::to_string(id));

            for (auto& attach : attachIds) {
                std::string attname;

                genericItem.GetAttachmentName(attach, attname);
                WindowsUI::AttachmentField attField;
                attField.Title(winrt::to_hstring(attname));
                attField.Value(winrt::to_hstring(attach));
                attField.Download({ this, &VaultUI::Attachment_Download });

                OPENSSL_cleanse(attname.data(), attname.size());
                attname.clear();

                SidebarAttachments().Children().Append(attField);
            }

            genericItem.Close();

            ClientWarden::Vault::Folder folderItem(vault, folder);

            /*
            * Secret Data
            */
            std::string folderName = "";

            folderItem.GetName(folderName)
                    .Close();
            
            mt_folderPick = true;
            FolderPicker().Value(winrt::to_hstring(folderName));
            mt_folderPick = false;

            OPENSSL_cleanse(folderName.data(), folderName.size());
            folderName.clear();
        } catch (const std::exception& e) {
            logger->error("PopulateSidePane ~ exception: {}", e.what());
        } catch (...) {
            logger->error("PopulateSidePane ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::SidebarEdit_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            winrt::apartment_context ui_thread;

            SidebarEditMode();

            std::string id = winrt::to_string(SidebarId().Text());
            std::string type = winrt::to_string(SidebarType().Text());

            SidebarCard().Children().Clear();
            SidebarFields().Children().Clear();

            mt_folderPick = true;
            FolderPicker().GetComboBox().IsEnabled(true);
            FolderPicker().GetComboBox().ClearValue(winrt::Microsoft::UI::Xaml::Controls::Control::BorderBrushProperty());
            FolderPicker().GetComboBox().ClearValue(winrt::Microsoft::UI::Xaml::Controls::Control::BackgroundProperty());
            mt_folderPick = false;

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

                co_await winrt::resume_background();

                loginItem.GetUsername(username)
                         .GetPassword(password)
                         .GetTotpSecret(totp)
                         .GetWebsites(websites)
                         .GetNotes(notes)
                         .GetFields(fields)
                         .GetFavorite(fav)
                         .GetAttachmentIDs(attachIds)
                         .Close();

                co_await ui_thread;
                
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

                co_await winrt::resume_background();

                OPENSSL_cleanse(username.data(), username.size());
                username.clear();
                OPENSSL_cleanse(password.data(), password.size());
                password.clear();
                OPENSSL_cleanse(totp.data(), totp.size());
                totp.clear();

                co_await ui_thread;
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

                co_await winrt::resume_background();

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
                            .GetAttachmentIDs(attachIds)
                            .Close();

                co_await ui_thread;
                
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

                co_await winrt::resume_background();

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

                co_await ui_thread;
            } else if (type == "Card") {
                ClientWarden::Vault::CardItem cardItem(vault, id);

                std::string cardholderName;
                std::string number;
                std::string expirationMonth;
                std::string expirationYear;
                std::string cvv;
                std::string brand;

                co_await winrt::resume_background();

                cardItem.GetCardholderName(cardholderName)
                        .GetNumber(number)
                        .GetExpMonth(expirationMonth)
                        .GetExpYear(expirationYear)
                        .GetCode(cvv)
                        .GetBrand(brand)
                        .GetNotes(notes)
                        .GetFields(fields)
                        .GetFavorite(fav)
                        .GetAttachmentIDs(attachIds)
                        .Close();

                co_await ui_thread;
                
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

                co_await winrt::resume_background();

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

                co_await ui_thread;
            } else if (type == "Note") {
                ClientWarden::Vault::NoteItem noteItem(vault, id);

                co_await winrt::resume_background();

                noteItem.GetNotes(notes)
                        .GetFields(fields)
                        .GetFavorite(fav)
                        .GetAttachmentIDs(attachIds)
                        .Close();

                co_await ui_thread;
            } else if (type == "SSHKey") {
                ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, id);

                std::string privKey;
                std::string pubKey;
                std::string fingerprint;

                co_await winrt::resume_background();

                sshkeyItem.GetPrivateKey(privKey)
                          .GetPublicKey(pubKey)
                          .GetFingerprint(fingerprint)
                          .GetNotes(notes)
                          .GetFields(fields)
                          .GetFavorite(fav)
                          .GetAttachmentIDs(attachIds)
                          .Close();

                co_await ui_thread;
                
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

                co_await winrt::resume_background();

                OPENSSL_cleanse(privKey.data(), privKey.size());
                privKey.clear();
                OPENSSL_cleanse(pubKey.data(), pubKey.size());
                pubKey.clear();
                OPENSSL_cleanse(fingerprint.data(), fingerprint.size());
                fingerprint.clear();

                co_await ui_thread;
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
            
            ClientWarden::Vault::GenericItem genericItem(vault, id);

            for (auto& attach : attachIds) {
                std::string attname;

                genericItem.GetAttachmentName(attach, attname);

                WindowsUI::AttachmentEditField attField;
                attField.Title(winrt::to_hstring(attname));
                attField.Value(winrt::to_hstring(attach));
                attField.Bin([this, attField](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                    auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                    auto id = winrt::to_string(field.Value());

                    ClientWarden::Vault::GenericItem genericItem(vault, winrt::to_string(SidebarId().Text()));
                        
                    genericItem.RemoveAttachment(id)
                               .Close();
                    
                    uint32_t idx;
                    if (SidebarAttachments().Children().IndexOf(attField, idx)) {
                        SidebarAttachments().Children().RemoveAt(idx);
                    }
                        
                    co_return;
                });

                OPENSSL_cleanse(attname.data(), attname.size());
                attname.clear();

                SidebarAttachments().Children().Append(attField);
            }
        } catch (const std::exception& e) {
            logger->error("SidebarEdit_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("SidebarEdit_Click ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::SidebarSave_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            if (!isEdit) co_return;
            
            winrt::apartment_context ui_thread;

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

                co_await winrt::resume_background();

                loginItem.SetName(name)
                         .SetUsername(username)
                         .SetPassword(password)
                         .SetTotp(totp)
                         .GetWebsites(locWebsites)
                         .SetNotes(notes)
                         .GetFields(locFields);

                co_await ui_thread;
                
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

                co_await winrt::resume_background();

                loginItem.Commit();

                co_await ui_thread;
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

                co_await winrt::resume_background();

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

                co_await ui_thread;
                
                for (auto field : locFields) {
                    identityItem.RemoveField(std::get<1>(field));
                }

                for (auto field : fields) {
                    identityItem.AddField(std::get<0>(field), std::get<1>(field), std::get<2>(field));
                }

                co_await winrt::resume_background();

                identityItem.Commit();

                co_await ui_thread;
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

                co_await winrt::resume_background();

                cardItem.SetCardholderName(cardholderName)
                        .SetNumber(number)
                        .SetExpMonth(expirationMonth)
                        .SetExpYear(expirationYear)
                        .SetCode(cvv)
                        .SetBrand(brand)
                        .SetName(name)
                        .SetNotes(notes)
                        .GetFields(locFields);

                co_await ui_thread;
                
                for (auto field : locFields) {
                    cardItem.RemoveField(std::get<1>(field));
                }

                for (auto field : fields) {
                    cardItem.AddField(std::get<0>(field), std::get<1>(field), std::get<2>(field));
                }

                co_await winrt::resume_background();

                cardItem.Commit();

                co_await ui_thread;
            } else if (type == "Note") {
                ClientWarden::Vault::NoteItem noteItem(vault, id);

                std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> locFields;

                co_await winrt::resume_background();

                noteItem.SetNotes(notes)
                        .SetName(name)
                        .GetFields(locFields);

                co_await ui_thread;
                
                for (auto field : locFields) {
                    noteItem.RemoveField(std::get<1>(field));
                }

                for (auto field : fields) {
                    noteItem.AddField(std::get<0>(field), std::get<1>(field), std::get<2>(field));
                }

                co_await winrt::resume_background();

                noteItem.Commit();

                co_await ui_thread;
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

                co_await winrt::resume_background();

                sshkeyItem.SetPrivateKey(privKey)
                          .SetPublicKey(pubKey)
                          .SetFingerprint(fingerprint)
                          .SetName(name)
                          .SetNotes(notes)
                          .GetFields(locFields);

                co_await ui_thread;
                
                for (auto field : locFields) {
                    sshkeyItem.RemoveField(std::get<1>(field));
                }

                for (auto field : fields) {
                    sshkeyItem.AddField(std::get<0>(field), std::get<1>(field), std::get<2>(field));
                }

                co_await winrt::resume_background();

                sshkeyItem.Commit();

                co_await ui_thread;
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
        } catch (const std::exception& e) {
            logger->error("SidebarSave_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("SidebarSave_Click ~ exception");
        }
    }

    void VaultUI::SidebarCancel_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            SidebarViewMode();

            PopulateSidePane(SidebarId().Text(), SidebarTitle().Text(), SidebarType().Text(), SidebarImage().Source());
        } catch (const std::exception& e) {
            logger->error("SidebarCancel_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("SidebarCancel_Click ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::SidebarAttachment_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            winrt::apartment_context ui_thread;

            std::string id = winrt::to_string(SidebarId().Text());
            std::string type = winrt::to_string(SidebarType().Text());

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

            auto dispatcher = Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();

            WindowsUI::AttachmentField attField;
            attField.Title(file.Name());
            attField.Progress(0.01);

            SidebarAttachments().Children().Append(attField);

            co_await winrt::resume_background();

            ClientWarden::Vault::GenericItem genericItem(vault, id);

            std::string attCont;
            std::string attId = "";

            genericItem.AddAttachment(fileName, fileContents, attId,
                [this, attField, dispatcher](float progress) {
                    dispatcher.TryEnqueue([this, attField, progress]() {
                        attField.Progress(progress);
                    });
                })
                .Close();

            co_await ui_thread;

            attField.Progress(1.0);

            if (attId == "") {
                uint32_t idx;
                if (SidebarAttachments().Children().IndexOf(attField, idx)) {
                    SidebarAttachments().Children().RemoveAt(idx);
                }
                co_return;
            }

            attField.Value(winrt::to_hstring(attId));
            attField.Download({ this, &VaultUI::Attachment_Download });

            OPENSSL_cleanse(fileName.data(), fileName.size());
            fileName.clear();

            OPENSSL_cleanse(fileContents.data(), fileContents.size());
            fileContents.clear();

            co_return;
        } catch (const std::exception& e) {
            logger->error("SidebarAttachment_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("SidebarAttachment_Click ~ exception");
        }
        co_return;
    }

    winrt::fire_and_forget VaultUI::Favorite_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            winrt::apartment_context ui_thread;

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

            co_await winrt::resume_background();

            ClientWarden::Vault::GenericItem genericItem(vault, id);

            genericItem.SetFavorite(fav)
                       .Commit();
            
            co_await ui_thread;
        } catch (const std::exception& e) {
            logger->error("Favorite_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("Favorite_Click ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::Duplicate_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            winrt::apartment_context ui_thread;

            std::string id = winrt::to_string(SidebarId().Text());
            std::string type = winrt::to_string(SidebarType().Text());

            if (type == "Login") {
                co_await winrt::resume_background();
                ClientWarden::Vault::LoginItem loginItem(vault, id);

                std::string dupid;

                loginItem.Duplicate(dupid)
                         .Close();

                co_await ui_thread;

                PopulateItem({ClientWarden::Vault::CipherType::Login, dupid});
            } else if (type == "Card") {
                co_await winrt::resume_background();
                ClientWarden::Vault::CardItem cardItem(vault, id);

                std::string dupid;

                cardItem.Duplicate(dupid)
                        .Close();

                co_await ui_thread;

                PopulateItem({ClientWarden::Vault::CipherType::Card, dupid});
            } else if (type == "Identity") {
                co_await winrt::resume_background();
                ClientWarden::Vault::IdentityItem identityItem(vault, id);

                std::string dupid;

                identityItem.Duplicate(dupid)
                            .Close();

                co_await ui_thread;

                PopulateItem({ClientWarden::Vault::CipherType::Identity, dupid});
            } else if (type == "Note") {
                co_await winrt::resume_background();
                ClientWarden::Vault::NoteItem noteItem(vault, id);

                std::string dupid;

                noteItem.Duplicate(dupid)
                        .Close();

                co_await ui_thread;

                PopulateItem({ClientWarden::Vault::CipherType::Note, dupid});
            } else if (type == "SSHKey") {
                co_await winrt::resume_background();
                ClientWarden::Vault::SSHKeyItem sshItem(vault, id);

                std::string dupid;

                sshItem.Duplicate(dupid)
                       .Close();

                co_await ui_thread;

                PopulateItem({ClientWarden::Vault::CipherType::SSHKey, dupid});
            }
        } catch (const std::exception& e) {
            logger->error("Duplicate_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("Duplicate_Click ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::Delete_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            winrt::apartment_context ui_thread;

            std::string id = winrt::to_string(SidebarId().Text());
            std::string type = winrt::to_string(SidebarType().Text());

            co_await winrt::resume_background();

            ClientWarden::Vault::GenericItem genericItem(vault, id);

            genericItem.Bin();

            co_await ui_thread;

            auto items = VaultItemList().Children();
            for (uint32_t i = 0; i < items.Size(); i++) {
                if (auto item = items.GetAt(i).try_as<winrt::WindowsUI::VaultItem>()) {
                    if (winrt::to_string(item.itemID()) == id) {
                        items.RemoveAt(i);
                        break;
                    }
                }
            }
        } catch (const std::exception& e) {
            logger->error("Delete_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("Delete_Click ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::Perm_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            winrt::apartment_context ui_thread;

            std::string id = winrt::to_string(SidebarId().Text());
            std::string type = winrt::to_string(SidebarType().Text());

            co_await winrt::resume_background();
            
            ClientWarden::Vault::GenericItem genericItem(vault, id);

            genericItem.Delete();

            co_await ui_thread;

            auto items = VaultItemList().Children();
            for (uint32_t i = 0; i < items.Size(); i++) {
                if (auto item = items.GetAt(i).try_as<winrt::WindowsUI::VaultItem>()) {
                    if (winrt::to_string(item.itemID()) == id) {
                        items.RemoveAt(i);
                        break;
                    }
                }
            }
        } catch (const std::exception& e) {
            logger->error("Perm_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("Perm_Click ~ exception");
        }
    }

    winrt::fire_and_forget VaultUI::Restore_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            winrt::apartment_context ui_thread;

            std::string id = winrt::to_string(SidebarId().Text());
            std::string type = winrt::to_string(SidebarType().Text());

            co_await winrt::resume_background();
            
            ClientWarden::Vault::GenericItem genericItem(vault, id);

            genericItem.UnBin();

            co_await ui_thread;

            auto items = VaultItemList().Children();
            for (uint32_t i = 0; i < items.Size(); i++) {
                if (auto item = items.GetAt(i).try_as<winrt::WindowsUI::VaultItem>()) {
                    if (winrt::to_string(item.itemID()) == id) {
                        items.RemoveAt(i);
                        break;
                    }
                }
            }
        } catch (const std::exception& e) {
            logger->error("Restore_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("Restore_Click ~ exception");
        }
    }

    void VaultUI::LoginPasswordItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
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
        } catch (const std::exception& e) {
            logger->error("LoginPasswordItem_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("LoginPasswordItem_Click ~ exception");
        }
    }

    void VaultUI::NatIncIdentityItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
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
        } catch (const std::exception& e) {
            logger->error("NatIncIdentityItem_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("NatIncIdentityItem_Click ~ exception");
        }
    }
    
    void VaultUI::PassportIdentityItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
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
        } catch (const std::exception& e) {
            logger->error("PassportIdentityItem_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("PassportIdentityItem_Click ~ exception");
        }
    }

    void VaultUI::NumberCardItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
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
        } catch (const std::exception& e) {
            logger->error("NumberCardItem_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("NumberCardItem_Click ~ exception");
        }
    }

    void VaultUI::CVVCardItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
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
        } catch (const std::exception& e) {
            logger->error("CVVCardItem_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("CVVCardItem_Click ~ exception");
        }
    }

    void VaultUI::PrivSSHItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
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
        } catch (const std::exception& e) {
            logger->error("PrivSSHItem_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("PrivSSHItem_Click ~ exception");
        }
    }

    void VaultUI::HiddenItem_Click(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) {
        try {
            std::string id = winrt::to_string(SidebarId().Text());
            std::string type = winrt::to_string(SidebarType().Text());

            auto HidField = sender.as<WindowsUI::HiddenField>();
            std::string uri = winrt::to_string(HidField.GetShowHideImage().UriSource().RawUri());

            /*
            * SECRET DATA
            */
            std::vector<std::tuple<ClientWarden::Vault::CustomFieldType, std::string, std::string>> fields;

            ClientWarden::Vault::GenericItem genericItem(vault, id);

            genericItem.GetFields(fields)
                       .Close();

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
        } catch (const std::exception& e) {
            logger->error("HiddenItem_Click ~ exception: {}", e.what());
        } catch (...) {
            logger->error("HiddenItem_Click ~ exception");
        }
    }
}