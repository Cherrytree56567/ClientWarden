#pragma once
#include <memory>
#include "clientwarden.h"
#include "../network/network.h"
#include "../runtime/runtime.h"

namespace clientwarden::vault {
    class Versioning {
    public:
        Versioning(std::shared_ptr<Network> network, std::shared_ptr<Runtime> runtime);
        virtual ~Versioning() = default;

        /**
         * @brief Determine Version first checks the vault, then checks via network.
         * 
         * If the network check fails, return false and wait for the Vault to try again.
         */
        virtual bool determineVersion() = 0;

        /**
         * @brief hasFeature requires an int to allow multiple vendor types
         * 
         * An `enum class <VENDOR_NAME> : int` should be used.
         */
        virtual bool hasFeature(int feature) = 0;
        
        /**
         * @brief Used to provide the class's vendor.
         */
        virtual Vendor getVendor() = 0;
    protected:
        std::shared_ptr<Network> m_network;
        std::shared_ptr<Runtime> m_runtime;
    };
}