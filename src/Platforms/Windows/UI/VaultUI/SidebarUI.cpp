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

    void VaultUI::PopulateSidePane(winrt::hstring id, winrt::hstring title, winrt::hstring type, winrt::Microsoft::UI::Xaml::Media::ImageSource logo) {
        try {
            SidebarViewMode();

            SidebarImage().Source(logo);
            SidebarTitle().Text(title);
            SidebarType().Text(type);
            SidebarId().Text(id);

            SidebarCard().Children().Clear();
            SidebarFields().Children().Clear();
            SidebarAttachments().Children().Clear();
            SidebarNotes().Text(L"");

            FolderPicker().GetComboBox().IsEnabled(false);
            FolderPicker().GetComboBox().Background(winrt::Microsoft::UI::Xaml::Media::SolidColorBrush(winrt::Microsoft::UI::Colors::Transparent()));
            FolderPicker().GetComboBox().BorderBrush(winrt::Microsoft::UI::Xaml::Media::SolidColorBrush(winrt::Microsoft::UI::Colors::Transparent()));

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

                loginItem.GetUsername(username)
                         .GetPassword(password)
                         .GetTotp(totp)
                         .GetWebsites(websites)
                         .GetPasskeyCreationDate(passkeyCreation)
                         .GetNotes(notes)
                         .GetFields(fields)
                         .GetFavorite(fav)
                         .GetFolder(folder)
                         .GetAttachmentIDs(attachIds);
                
                /*
                 * TODO: Fix Attachments
                */
                for (auto& attach : attachIds) {
                    std::string attname;

                    loginItem.GetAttachmentName(attach, attname);
                    WindowsUI::AttachmentField attField;
                    attField.Title(winrt::to_hstring(attname));
                    attField.Value(winrt::to_hstring(attach));
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

                    OPENSSL_cleanse(attname.data(), attname.size());
                    attname.clear();

                    SidebarAttachments().Children().Append(attField);
                }

                loginItem.Close();
                
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

                OPENSSL_cleanse(username.data(), username.size());
                username.clear();
                OPENSSL_cleanse(totp.code.data(), totp.code.size());
                totp.code.clear();
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
                            .GetAttachmentIDs(attachIds);
                
                for (auto& attach : attachIds) {
                    std::string attname;

                    identityItem.GetAttachmentName(attach, attname);
                    WindowsUI::AttachmentField attField;
                    attField.Title(winrt::to_hstring(attname));
                    attField.Value(winrt::to_hstring(attach));
                    attField.Download([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                        auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                        auto id = winrt::to_string(field.Value());

                        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                        ClientWarden::Vault::IdentityItem identityItem(vault, winrt::to_string(SidebarId().Text()));

                        std::string attCont;
                        
                        identityItem.GetAttachment(id, attCont)
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

                    OPENSSL_cleanse(attname.data(), attname.size());
                    attname.clear();

                    SidebarAttachments().Children().Append(attField);
                }

                identityItem.Close();
                
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
            } else if (type == L"Card") {
                ClientWarden::Vault::CardItem cardItem(vault, winrt::to_string(id));

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
                        .GetFolder(folder)
                        .GetFields(fields)
                        .GetFavorite(fav)
                        .GetAttachmentIDs(attachIds);
                
                for (auto& attach : attachIds) {
                    std::string attname;

                    cardItem.GetAttachmentName(attach, attname);
                    WindowsUI::AttachmentField attField;
                    attField.Title(winrt::to_hstring(attname));
                    attField.Value(winrt::to_hstring(attach));
                    attField.Download([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                        auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                        auto id = winrt::to_string(field.Value());

                        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                        ClientWarden::Vault::CardItem cardItem(vault, winrt::to_string(SidebarId().Text()));

                        std::string attCont;
                        
                        cardItem.GetAttachment(id, attCont)
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

                    OPENSSL_cleanse(attname.data(), attname.size());
                    attname.clear();

                    SidebarAttachments().Children().Append(attField);
                }

                cardItem.Close();
                
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
            } else if (type == L"Note") {
                ClientWarden::Vault::NoteItem noteItem(vault, winrt::to_string(id));

                noteItem.GetNotes(notes)
                        .GetFolder(folder)
                        .GetFields(fields)
                        .GetFavorite(fav)
                        .GetAttachmentIDs(attachIds);
                
                for (auto& attach : attachIds) {
                    std::string attname;

                    noteItem.GetAttachmentName(attach, attname);
                    WindowsUI::AttachmentField attField;
                    attField.Title(winrt::to_hstring(attname));
                    attField.Value(winrt::to_hstring(attach));
                    attField.Download([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                        auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                        auto id = winrt::to_string(field.Value());

                        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                        ClientWarden::Vault::NoteItem noteItem(vault, winrt::to_string(SidebarId().Text()));

                        std::string attCont;
                        
                        noteItem.GetAttachment(id, attCont)
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

                    OPENSSL_cleanse(attname.data(), attname.size());
                    attname.clear();

                    SidebarAttachments().Children().Append(attField);
                }

                noteItem.Close();
            } else if (type == L"SSHKey") {
                ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, winrt::to_string(id));

                std::string privKey;
                std::string pubKey;
                std::string fingerprint;

                sshkeyItem.GetPrivateKey(privKey)
                        .GetPublicKey(pubKey)
                        .GetFingerprint(fingerprint)
                        .GetNotes(notes)
                        .GetFolder(folder)
                        .GetFields(fields)
                        .GetFavorite(fav)
                        .GetAttachmentIDs(attachIds);
                
                for (auto& attach : attachIds) {
                    std::string attname;

                    sshkeyItem.GetAttachmentName(attach, attname);
                    WindowsUI::AttachmentField attField;
                    attField.Title(winrt::to_hstring(attname));
                    attField.Value(winrt::to_hstring(attach));
                    attField.Download([this](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& e) -> winrt::fire_and_forget {
                        auto field = sender.as<winrt::WindowsUI::AttachmentField>();
                        auto id = winrt::to_string(field.Value());

                        ClientWarden::Vault::Vault& vault = ClientWarden::Vault::Vault::Instance();

                        ClientWarden::Vault::SSHKeyItem sshkeyItem(vault, winrt::to_string(SidebarId().Text()));

                        std::string attCont;
                        
                        sshkeyItem.GetAttachment(id, attCont)
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

                    OPENSSL_cleanse(attname.data(), attname.size());
                    attname.clear();

                    SidebarAttachments().Children().Append(attField);
                }

                sshkeyItem.Close();

                std::string hidnum;
                
                for (int i = 0; i < privKey.size(); i++) {
                    hidnum = hidnum + "•";
                }
                
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

            ClientWarden::Vault::Folder folderItem(vault, folder);

            /*
            * Secret Data
            */
            std::string folderName = "";

            folderItem.GetName(folderName)
                    .Close();
            
            FolderPicker().Value(winrt::to_hstring(folderName));

            OPENSSL_cleanse(folderName.data(), folderName.size());
            folderName.clear();
        } catch (const std::exception& e) {
            logger->error("SidebarEmptyMode ~ exception: {}", e.what());
        } catch (...) {
            logger->error("SidebarEmptyMode ~ exception");
        }
    }
}