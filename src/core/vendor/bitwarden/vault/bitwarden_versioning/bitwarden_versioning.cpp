#include "bitwarden_versioning.h"

namespace clientwarden::vendor::bitwarden::vault {
    BitwardenVersioning::BitwardenVersioning(std::shared_ptr<Network> network, 
        std::shared_ptr<Runtime> runtime) : Versioning(network, runtime), m_init(false) {
        
    }

    /**
     * @brief Get the network version
     * @example version 2026.2.0
     */
    bool BitwardenVersioning::determineVersion() {
        m_init = false;

        std::expected<Botan::secure_vector<uint8_t>, NetworkError> net_version = 
            m_network->getVersion();
        
        std::expected<Botan::secure_vector<uint8_t>, RuntimeError> run_version = 
            m_runtime->getVersion();
        
        if (!net_version.has_value()) {
            if (!run_version.has_value()) {
                return false;
            }

            std::optional<semver::version> run_ver = 
                semver::from_string_noexcept(utils::getString(run_version.value()));
            
            if (!run_ver.has_value()) {
                return false;
            }

            m_version_ = run_ver.value();
            
            m_init = true;

            return true;
        }

        /**
         * @brief Compare values (2026.2.0) of net_version and run_version.
         */
        if (run_version.has_value()) {
            std::optional<semver::version> net_ver = 
                semver::from_string_noexcept(utils::getString(net_version.value()));
            std::optional<semver::version> run_ver = 
                semver::from_string_noexcept(utils::getString(run_version.value()));
            
            if (!net_ver.has_value()) {
                if (!run_ver.has_value()) {
                    return false;
                }

                m_version_ = run_ver.value();
                
                m_init = true;

                return true;
            }

            if (!run_ver.has_value()) {
                m_version_ = net_ver.value();
                
                m_init = true;

                return true;
            }

            if (net_ver.value() > run_ver.value()) {
                m_version_ = net_ver.value();

                RuntimeError run_err = m_runtime->storeVersion(net_version.value());

                if (run_err != RuntimeError::Success) {
                    m_init = true;

                    return false;
                }
            } else {
                m_version_ = run_ver.value();
            }
        } else {
            std::optional<semver::version> net_ver = 
                semver::from_string_noexcept(utils::getString(net_version.value()));
            
            if (!net_ver.has_value()) {
                return false;
            }
            
            m_version_ = net_ver.value();
        }

        m_init = true;

        return true;
    }

    std::expected<bool, VersioningError> BitwardenVersioning::hasFeature(int num_feature) {
        if (!m_init) {
            return std::unexpected(VersioningError::Uninitialised);
        }

        BitwardenFeature feature = static_cast<BitwardenFeature>(num_feature);

        switch (feature) {
            case BitwardenFeature::DataField:
                return m_version_ < semver::version(2026, 6, 0);
            case BitwardenFeature::BankAccount:
                return m_version_ >= semver::version(2026, 8, 1);
            case BitwardenFeature::Passport:
                return m_version_ >= semver::version(2026, 8, 1);
            case BitwardenFeature::DriversLicense:
                return m_version_ >= semver::version(2026, 8, 1);
            default:
                return std::unexpected(VersioningError::UnknownFeature);
        }
    }
        
    Vendor BitwardenVersioning::getVendor() {
        return Vendor::BitWarden;
    }
}