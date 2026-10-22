#pragma once
#include "vault/versioning/versioning.h"

namespace clientwarden::vendor::bitwarden::vault {
    class BitwardenVersioning : public Versioning {
    public:
        explicit BitwardenVersioning(std::shared_ptr<Network> network, 
            std::shared_ptr<Runtime> runtime);
        ~BitwardenVersioning() override = default;

        bool determineVersion() override;

        bool hasFeature(int feature) override;
        
        Vendor getVendor() override;
    private:
        std::string m_version_;
        bool m_init = false;
    };
}