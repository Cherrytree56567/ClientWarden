#pragma once
#include "vault/versioning/versioning.h"
#include <semver.hpp>

namespace clientwarden::vendor::bitwarden::vault {
    enum class BitwardenFeature : int {
        DataField,
        BankAccount,
        Passport,
        DriversLicense
    };

    class BitwardenVersioning : public Versioning {
    public:
        explicit BitwardenVersioning(std::shared_ptr<Network> network, 
            std::shared_ptr<Runtime> runtime);
        ~BitwardenVersioning() override = default;

        bool determineVersion() override;

        std::expected<bool, VersioningError> hasFeature(int feature) override;
        
        Vendor getVendor() override;
    private:
        semver::version m_version_;
        bool m_init = false;
    };
}