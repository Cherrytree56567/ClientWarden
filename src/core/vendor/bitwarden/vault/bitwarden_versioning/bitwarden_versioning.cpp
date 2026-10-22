#include "bitwarden_versioning.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenVersioning::BitwardenVersioning(std::shared_ptr<Network> network, 
        std::shared_ptr<Runtime> runtime) : Versioning(network, runtime) {
        
    }

    /**
     * @brief Get the network version
     * @example version 2026.2.0
     */
    bool BitwardenVersioning::determineVersion() {
        std::expected<Botan::secure_vector<uint8_t>, NetworkError> net_version = 
            m_network->getVersion();
        
        std::expected<Botan::secure_vector<uint8_t>, RuntimeError> run_version = 
            m_runtime->getVersion();
        
        if (!net_version.has_value()) {
            if (!run_version.has_value()) {
                return false;
            }

            m_version_ = utils::getString(run_version.value());

            return true;
        }

        /**
         * @todo Compare values (2026.2.0) of net_version and run_version.
         */
        if (run_version.has_value() && (net_version.value() > run_version.value())) {
            m_version_ = utils::getString(net_version.value());

            RuntimeError run_err = m_runtime->storeVersion(net_version.value());

            if (run_err != RuntimeError::Success) {
                return false;
            }
        }

        return true;
    }

    bool BitwardenVersioning::hasFeature(int feature) {

    }
        
    Vendor BitwardenVersioning::getVendor() {
        return Vendor::BitWarden;
    }
}