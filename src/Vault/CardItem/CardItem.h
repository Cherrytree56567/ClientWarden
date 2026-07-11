#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "../GenericItem/GenericItemImpl.h"

namespace ClientWarden {
    class CardItem : public GenericItemImpl<CardItem> {
    public:
        CardItem(Vault& vault, std::string uuid); // Existing Item
        CardItem(Vault& vault); // New Item

        CardItem* SetBrand(std::string& brand);
        CardItem* SetCardholderName(std::string& cardholderName);
        CardItem* SetCode(std::string& code);
        CardItem* SetExpMonth(std::string& expMonth);
        CardItem* SetExpYear(std::string& expYear);
        CardItem* SetNumber(std::string& number);

        CardItem* Duplicate(std::string& id);

        /*
         * Secret Data
        */
        CardItem* GetBrand(std::string& brand);
        CardItem* GetCardholderName(std::string& cardholderName);
        CardItem* GetCode(std::string& code);
        CardItem* GetExpMonth(std::string& expMonth);
        CardItem* GetExpYear(std::string& expYear);
        CardItem* GetNumber(std::string& number);

        CardItem* GetType(CipherType& val);
    private:
        inline static std::shared_ptr<spdlog::logger> l_logger = nullptr;
    };
}