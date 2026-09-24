#pragma once
#include <string>

namespace clientwarden::vault {
    enum class OrganisationRole {
        Owner, 
        Admin,
        User,
        Custom
    };

    struct OrganisationMembership {
        boost::uuids::uuid id;
        Botan::secure_vector<uint8_t> name;
        OrganisationRole role;
        bool enabled;
    };

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