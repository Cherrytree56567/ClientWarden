#pragma once
#include "GenericItem/GenericItem.h"

namespace ClientWarden {
    template <typename Derived>
    class GenericItemImpl : public GenericItem {
    public:
        Derived* SetName(std::string& name) override {
            GenericItem::SetName(name);
            return static_cast<Derived*>(this);
        }
        
        Derived* SetNotes(std::string& notes) override {
            GenericItem::SetNotes(notes);
            return static_cast<Derived*>(this);
        }
        
        Derived* SetFolder(std::string folder) override {
            GenericItem::SetFolder(folder);
            return static_cast<Derived*>(this);
        }
        
        Derived* RemoveFolder() override {
            GenericItem::RemoveFolder();
            return static_cast<Derived*>(this);
        }
        
        Derived* AddField(CustomFieldType field, std::string& name, std::string& value) override {
            GenericItem::AddField(field, name, value);
            return static_cast<Derived*>(this);
        }
        
        Derived* RemoveField(std::string& name) override {
            GenericItem::RemoveField(name);
            return static_cast<Derived*>(this);
        }
        
        Derived* ClearFields() override {
            GenericItem::ClearFields();
            return static_cast<Derived*>(this);
        }
        
        Derived* GetName(std::string& name) override {
            GenericItem::GetName(name);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetNotes(std::string& notes) override {
            GenericItem::GetNotes(notes);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetFolder(std::string& folder) override {
            GenericItem::GetFolder(folder);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetFields(std::vector<std::tuple<CustomFieldType, std::string, std::string>>& value) override {
            GenericItem::GetFields(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetId(std::string& value) override {
            GenericItem::GetId(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetCreation(std::string& value) override {
            GenericItem::GetCreation(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetModification(std::string& value) override {
            GenericItem::GetModification(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetDeletion(std::string& value) override {
            GenericItem::GetDeletion(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* AddAttachment(std::string& name, std::string& content, std::string& id, std::function<void(float)> onProgress = nullptr) 
            override {
            GenericItem::AddAttachment(name, content, id, onProgress);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetAttachmentIDs(std::vector<std::string>& ids) override {
            GenericItem::GetAttachmentIDs(ids);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetAttachmentName(std::string id, std::string& name) override {
            GenericItem::GetAttachmentName(id, name);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetAttachment(std::string id, std::string& content, std::function<void(float)> onProgress = nullptr) override {
            GenericItem::GetAttachment(id, content, onProgress);
            return static_cast<Derived*>(this);
        }
        
        Derived* RemoveAttachment(std::string id) override {
            GenericItem::RemoveAttachment(id);
            return static_cast<Derived*>(this);
        }
        
        
        Derived* SetFavorite(bool val) override {
            GenericItem::SetFavorite(value);
            return static_cast<Derived*>(this);
        }
        
        Derived* SetReprompt(bool val) override {
            GenericItem::SetReprompt(val);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetFavorite(bool& val) override {
            GenericItem::GetFavorite(val);
            return static_cast<Derived*>(this);
        }
        
        Derived* GetReprompt(bool& val) override {
            GenericItem::GetReprompt(val);
            return static_cast<Derived*>(this);
        }
    };
}