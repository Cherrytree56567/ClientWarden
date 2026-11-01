#include "Clipboard.h"

namespace ClientWarden {
    void Clipboard::Copy(std::string& str) {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackage dataPackage;

        winrt::hstring hstr = winrt::to_hstring(str);

        dataPackage.SetText(hstr);

        winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions options;
        options.IsRoamable(false);
        options.IsAllowedInHistory(false);

        winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContentWithOptions(dataPackage, options);

        DWORD targetedSequenceNumber = ::GetClipboardSequenceNumber();
        int delay = GetDelay();

        std::thread([delay, targetedSequenceNumber]() {
            std::this_thread::sleep_for(std::chrono::seconds(delay));
            if (GetClipboardSequenceNumber() == targetedSequenceNumber) {
                winrt::Windows::ApplicationModel::DataTransfer::DataPackage emptyPackage;
                emptyPackage.SetText(L"");
                    
                winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions emptyOptions;
                emptyOptions.IsRoamable(false);
                emptyOptions.IsAllowedInHistory(false);
                    
                winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContentWithOptions(emptyPackage, emptyOptions);
            }
        }).detach();

        if (!hstr.empty()) {
            void* hstrPtr = const_cast<wchar_t*>(hstr.data());
            size_t hstrBytes = hstr.size() * sizeof(wchar_t);
            OPENSSL_cleanse(hstrPtr, hstrBytes);
        }
        if (!str.empty()) {
            void* strPtr = const_cast<char*>(str.data());
            OPENSSL_cleanse(strPtr, str.size());
        }
    }

    void Clipboard::Paste(std::string& str) {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageView content = winrt::Windows::ApplicationModel::DataTransfer::Clipboard::GetContent();

        if (content.Contains(winrt::Windows::ApplicationModel::DataTransfer::StandardDataFormats::Text())) {
            winrt::hstring hstr = content.GetTextAsync().get();
            str = winrt::to_string(hstr);
            if (!hstr.empty()) {
                void* hstrPtr = const_cast<wchar_t*>(hstr.data());
                size_t hstrBytes = hstr.size() * sizeof(wchar_t);
                OPENSSL_cleanse(hstrPtr, hstrBytes);
            }
        } else {
            str = "";
        }
    }
}