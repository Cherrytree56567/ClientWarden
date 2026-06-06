#include "pch.h"
#include "VaultUI.xaml.h"

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::WindowsUI::implementation
{
    void VaultUI::DisplayFolder(std::string id) {
        try {
            ClientWarden::Vault::Folder folderItem(vault, id);

            /*
            * SECRET DATA
            */
            std::string folderName;

            folderItem.GetName(folderName)
                      .Close();
            
            /*
            * TODO: Use Botan and D2D Drawing to prevent leaking
            */
            winrt::hstring hFolderName = winrt::to_hstring(folderName);

            OPENSSL_cleanse(folderName.data(), folderName.size());
            folderName.clear();
                
            FolderPicker().AddOption(hFolderName);
            
            /*
            * UI Setup to display the folder item
            */
            winrt::Microsoft::UI::Xaml::Controls::NavigationViewItem item;

            winrt::Microsoft::UI::Xaml::Controls::Grid panel;
            panel.HorizontalAlignment(winrt::Microsoft::UI::Xaml::HorizontalAlignment::Stretch);
            panel.ColumnSpacing(8);

            winrt::Microsoft::UI::Xaml::Controls::ColumnDefinition col1;
            col1.Width(winrt::Microsoft::UI::Xaml::GridLength{ 1, winrt::Microsoft::UI::Xaml::GridUnitType::Star });
            winrt::Microsoft::UI::Xaml::Controls::ColumnDefinition col2;
            col2.Width(winrt::Microsoft::UI::Xaml::GridLength{ 16, winrt::Microsoft::UI::Xaml::GridUnitType::Pixel });

            panel.ColumnDefinitions().Append(col1);
            panel.ColumnDefinitions().Append(col2);

            winrt::Microsoft::UI::Xaml::Controls::TextBox itemBox;
            itemBox.Text(hFolderName);
            itemBox.BorderThickness(winrt::Microsoft::UI::Xaml::Thickness{ 0, 0, 0, 0 });
            itemBox.Background(winrt::Microsoft::UI::Xaml::Media::SolidColorBrush{ winrt::Microsoft::UI::Colors::Transparent() });
            itemBox.VerticalAlignment(winrt::Microsoft::UI::Xaml::VerticalAlignment::Center);
            itemBox.HorizontalAlignment(winrt::Microsoft::UI::Xaml::HorizontalAlignment::Stretch);
            itemBox.Tapped([](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Input::TappedRoutedEventArgs const& args) {
                args.Handled(true);
            });
            itemBox.LostFocus([this, id](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args) {
                auto box = sender.as<winrt::Microsoft::UI::Xaml::Controls::TextBox>();
                std::string newName = winrt::to_string(box.Text());
                    
                ClientWarden::Vault::Folder fold(vault, id);

                fold.SetName(newName)
                    .Commit();
                    
                mt_folderPick = true;

                FolderPicker().GetComboBox().Items().Clear();

                winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem emptyItem;
                emptyItem.Content(winrt::box_value(winrt::hstring(L"")));
                FolderPicker().GetComboBox().Items().Append(emptyItem);

                for (auto& foldId : vault.GetFolders()) {
                    ClientWarden::Vault::Folder folde(vault, foldId);

                    std::string foldName;

                    folde.GetName(foldName)
                        .Close();

                    winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem comboBoxItem;
                    comboBoxItem.Content(winrt::box_value(winrt::to_hstring(foldName)));

                    FolderPicker().GetComboBox().Items().Append(comboBoxItem);

                    OPENSSL_cleanse(foldName.data(), foldName.size());
                    foldName.clear();
                }

                FolderPicker().Value(winrt::to_hstring(newName));

                mt_folderPick = false;

                if (!SidebarId().Text().empty()) {
                    PopulateSidePane(SidebarId().Text(), SidebarTitle().Text(), SidebarType().Text(), SidebarImage().Source());
                }

                OPENSSL_cleanse(newName.data(), newName.size());
                newName.clear();
            });

            winrt::Microsoft::UI::Xaml::Controls::Grid::SetColumn(itemBox, 0);

            panel.Children().Append(itemBox);

            winrt::Microsoft::UI::Xaml::Controls::Image image;
            image.Width(16);
            image.Height(16);
            image.Source(winrt::Microsoft::UI::Xaml::Media::Imaging::BitmapImage(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_delete_24_regular.png")));
            image.Margin(winrt::Microsoft::UI::Xaml::Thickness{ 0, 0, -8, 0 });
            image.Tapped([this, id](winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Input::TappedRoutedEventArgs const& args) {                
                ClientWarden::Vault::Folder fold(vault, id);

                fold.Delete();

                auto menuItems = NavView().MenuItems();
                winrt::hstring targetName = winrt::to_hstring(id);

                for (uint32_t i = 0; i < menuItems.Size(); ++i) {
                    if (auto navItem = menuItems.GetAt(i).try_as<winrt::Microsoft::UI::Xaml::Controls::NavigationViewItem>()) {
                        if (navItem.Name() == targetName) {
                            menuItems.RemoveAt(i);
                            break;
                        }
                    }
                }
            });

            winrt::Microsoft::UI::Xaml::Controls::Grid::SetColumn(image, 1);

            panel.Children().Append(image);
            
            item.Content(panel);
            item.Name(winrt::to_hstring(id));

            winrt::Microsoft::UI::Xaml::Controls::BitmapIcon icon;
            icon.UriSource(winrt::Windows::Foundation::Uri(L"ms-appx:///Assets/ic_fluent_folder_24_regular.png"));
            icon.ShowAsMonochrome(true);
            item.Icon(icon);

            NavView().MenuItems().Append(item);
        } catch (const std::exception& e) {
            logger->error("DisplayFolder ~ exception: {}", e.what());
        } catch (...) {
            logger->error("DisplayFolder ~ exception");
        }
    }

    void VaultUI::FolderPickerSelectionChanged(winrt::Windows::Foundation::IInspectable const& sender, winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args) {
        try {
            if (mt_folderPick) {
                return;
            }
            auto box = sender.as<winrt::Microsoft::UI::Xaml::Controls::ComboBox>();
            auto selected = box.SelectedItem().as<winrt::Microsoft::UI::Xaml::Controls::ComboBoxItem>();
            std::string value = winrt::to_string(winrt::unbox_value<winrt::hstring>(selected.Content()));

            std::vector<std::string> folderIds = vault.GetFolders();

            std::string selectedFolder = "";

            for (auto& folder : folderIds) {
                ClientWarden::Vault::Folder folderItem(vault, folder);

                /*
                 * Secret Data
                */
                std::string folderName = "";

                folderItem.GetName(folderName)
                          .Close();
                        
                if (folderName == value) {
                    selectedFolder = folder;
                }

                OPENSSL_cleanse(folderName.data(), folderName.size());
                folderName.clear();
            }

            OPENSSL_cleanse(value.data(), value.size());
            value.clear();

            std::string id = winrt::to_string(SidebarId().Text());
            std::string type = winrt::to_string(SidebarType().Text());

            ClientWarden::Vault::GenericItem genericItem(vault, id);

            genericItem.SetFolder(selectedFolder)
                       .Commit();
        } catch (const std::exception& e) {
            logger->error("FolderPickerSelectionChanged ~ exception: {}", e.what());
        } catch (...) {
            logger->error("FolderPickerSelectionChanged ~ exception");
        }
    }
}