#pragma once
#include "GenericItem/GenericItem.h"

#include "VaultUtils/VaultUtils.h"

namespace ClientWarden {
    template <typename Derived>
    class GenericItemImpl : public GenericItem {
    public:
        using GenericItem::GenericItem;

        Derived* SetName(std::string& name) {
            GenericItem::SetNameImpl(name);
            return static_cast<Derived*>(this);
        }
        
        Derived* SetNotes(std::string& notes) {
            GenericItem::SetNotesImpl(notes);
            return static_cast<Derived*>(this);
        }
        
        Derived* SetFolder(std::string folder) {
            GenericItem::SetFolderImpl(folder);
            return static_cast<Derived*>(this);
        }
        
        Derived* RemoveFolder() {
            GenericItem::RemoveFolderImpl();
            return static_cast<Derived*>(this);
        }
        
        Derived* AddField(CustomFieldType field, std::string& name, std::string& value) {
            GenericItem::AddFieldImpl(field, name, value);
            return static_cast<Derived*>(this);
        }
        
        Derived* RemoveField(std::string& name) {
            GenericItem::RemoveFieldImpl(name);
            return static_cast<Derived*>(this);
        }
        
        Derived* ClearFields() {
            GenericItem::ClearFieldsImpl();
            return static_cast<Derived*>(this);
        }
        
        Derived* GetName(std::string& name) {
            GenericItem::GetNameImpl(name);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetNotes(std::string& notes) {
            GenericItem::GetNotesImpl(notes);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetFolder(std::string& folder) {
            GenericItem::GetFolderImpl(folder);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value) {
            GenericItem::GetFieldsImpl(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetId(std::string& value) {
            GenericItem::GetIdImpl(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetCreation(std::string& value) {
            GenericItem::GetCreationImpl(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetModification(std::string& value) {
            GenericItem::GetModificationImpl(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetDeletion(std::string& value) {
            GenericItem::GetDeletionImpl(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr) {
            GenericItem::AddAttachmentImpl(name, content, id, onProgress);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetAttachmentIDs(std::vector<std::string>& ids) {
            GenericItem::GetAttachmentIDsImpl(ids);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetAttachmentName(std::string id, std::string& name) {
            GenericItem::GetAttachmentNameImpl(id, name);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetAttachment(std::string id, std::filesystem::path filePath, std::function<void(float)> onProgress = nullptr) {
            GenericItem::GetAttachmentImpl(id, filePath, onProgress);
            return static_cast<Derived*>(this);
        }
        
        Derived* RemoveAttachment(std::string id) {
            GenericItem::RemoveAttachmentImpl(id);
            return static_cast<Derived*>(this);
        }
        
        Derived* SetFavorite(bool val) {
            GenericItem::SetFavoriteImpl(val);
            return static_cast<Derived*>(this);
        }
        
        Derived* SetReprompt(bool val) {
            GenericItem::SetRepromptImpl(val);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetFavorite(bool& val) {
            GenericItem::GetFavoriteImpl(val);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetReprompt(bool& val) {
            GenericItem::GetRepromptImpl(val);
            return static_cast<Derived*>(this);
        }
    };
}