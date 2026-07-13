#pragma once
#include <algorithm>
#include <botan/secmem.h>
#include <botan/hash.h>
#include <botan/otp.h>
#include <boost/url.hpp>
#include <botan/base32.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "Clientwarden.h"

namespace ClientWarden {
    class Vault;
    
    class GenericItem {
    public:
        GenericItem(Vault& vault, std::string uuid); // Existing Item
        GenericItem(Vault& vault); // New Item (needs to be initialised by a derived class)
        ~GenericItem();

        GenericItem* SetName(std::string& name);
        GenericItem* SetNotes(std::string& notes);
        GenericItem* SetFolder(std::string folder);
        GenericItem* RemoveFolder();
        GenericItem* AddField(CustomFieldType field, std::string& name, std::string& value);
        GenericItem* RemoveField(std::string& name);
        GenericItem* ClearFields();

        GenericItem* GetName(std::string& name);
        GenericItem* GetNotes(std::string& notes);
        GenericItem* GetFolder(std::string& folder);
        GenericItem* GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value);
        GenericItem* GetId(std::string& value);
        GenericItem* GetCreation(std::string& value);
        GenericItem* GetModification(std::string& value);
        GenericItem* GetDeletion(std::string& value);
        
        GenericItem* AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr);
        GenericItem* GetAttachmentIDs(std::vector<std::string>& ids);
        GenericItem* GetAttachmentName(std::string id, std::string& name);
        GenericItem* GetAttachment(std::string id, std::filesystem::path filePath, std::function<void(float)> onProgress = nullptr);
        GenericItem* RemoveAttachment(std::string id);
        
        GenericItem* SetFavorite(bool val);
        GenericItem* SetReprompt(bool val);
        GenericItem* GetFavorite(bool& val);
        GenericItem* GetReprompt(bool& val);
        GenericItem* GetType(CipherType& val);

        void Commit();
        void Delete();
        void Bin();
        void UnBin();
        void Close();
    protected:
        void SetNameImpl(std::string& name);
        void SetNotesImpl(std::string& notes);
        void SetFolderImpl(std::string folder);
        void RemoveFolderImpl();
        void AddFieldImpl(CustomFieldType field, std::string& name, std::string& value);
        void RemoveFieldImpl(std::string& name);
        void ClearFieldsImpl();

        void GetNameImpl(std::string& name);
        void GetNotesImpl(std::string& notes);
        void GetFolderImpl(std::string& folder);
        void GetFieldsImpl(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value);
        void GetIdImpl(std::string& value);
        void GetCreationImpl(std::string& value);
        void GetModificationImpl(std::string& value);
        void GetDeletionImpl(std::string& value);
        
        void AddAttachmentImpl(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr);
        void GetAttachmentIDsImpl(std::vector<std::string>& ids);
        void GetAttachmentNameImpl(std::string id, std::string& name);
        void GetAttachmentImpl(std::string id, std::filesystem::path filePath, std::function<void(float)> onProgress = nullptr);
        void RemoveAttachmentImpl(std::string id);
        
        void SetFavoriteImpl(bool val);
        void SetRepromptImpl(bool val);
        void GetFavoriteImpl(bool& val);
        void GetRepromptImpl(bool& val);

    protected:
        /*
         * Secret Data
        */
        Botan::secure_vector<uint8_t> itemEncKey;
        Botan::secure_vector<uint8_t> itemMacKey;

        bool isBeingCreated;
        bool init;
        nlohmann::json data;
        nlohmann::json fieldData;
        Vault& localVault;
    };
}