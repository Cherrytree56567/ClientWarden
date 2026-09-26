#pragma once
#include <string>
#include <vector>
#include <botan/secmem.h>
#include <nlohmann/json.hpp>

namespace clientwarden::vault {
    /**
     * @brief Represents a User's role in an Organisation
     */
    enum class OrganisationRole {
        Owner, 
        Admin,
        User,
        Custom
    };

    /**
     * @brief Represents the User's membership in an Organisation
     * @param id Organisation ID
     * @param name Organisation Name
     * @param role User's role in the Organisation
     * @param enabled Weather the membership is active
     */
    struct OrganisationMembership {
        ItemId id;
        Botan::secure_vector<uint8_t> name;
        OrganisationRole role;
        bool enabled;
    };

    /**
     * @brief Represents the User's Profile
     */
    struct Profile {
        Botan::secure_vector<uint8_t> email;
        Botan::secure_vector<uint8_t> name;
        bool premium;
        std::vector<OrganisationMembership> organisations;
        bool multi_factor_enabled;
        Botan::secure_vector<uint8_t> security_stamp;
        std::time_t creation_date;
        std::string avatar_color;
        nlohmann::json raw;
    };
}