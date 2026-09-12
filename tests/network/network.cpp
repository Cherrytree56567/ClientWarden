#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include "VaultNetwork/VaultNetwork.h"

TEST_CASE("preLogin Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string email = "email@a.com";

    std::optional<nlohmann::json> result = network.preLogin(email);

    bool urlTest = httplib::g_h_data.url == "/identity/accounts/prelogin";
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();
    bool valueTest = nlohmann::json::accept(httplib::g_h_data.value);
    bool valueValidTest = false;
    bool typeTest = httplib::g_h_data.type == "application/json";

    if (valueTest) {
        nlohmann::json p_value = nlohmann::json::parse(httplib::g_h_data.value);
        valueValidTest = p_value.contains("email") && p_value["email"].is_string();
    }

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(valueTest);
    CHECK(valueValidTest);
    CHECK(typeTest);
}

TEST_CASE("getToken Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string email = "email@a.com";
    std::string masterPasswordHash = "h@sh-d0nt-sh@r3-p1e@s3";

    std::optional<nlohmann::json> result = network.getToken(email, masterPasswordHash);

    bool urlTest = httplib::g_h_data.url == "/identity/connect/token";
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();

    auto a_it = httplib::g_h_data.headers.find("Accept");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto c_it = httplib::g_h_data.headers.find("Content-Type");
    bool contentTest = (c_it != httplib::g_h_data.headers.end() && c_it->second == "application/x-www-form-urlencoded; charset=utf-8");

    auto g_it = httplib::g_h_data.params.find("grant_type");
    bool grantTypeTest = g_it != httplib::g_h_data.params.end() && g_it->second == "password";

    auto u_it = httplib::g_h_data.params.find("username");
    bool usernameTest = u_it != httplib::g_h_data.params.end() && u_it->second == email;

    auto p_it = httplib::g_h_data.params.find("password");
    bool passwordTest = p_it != httplib::g_h_data.params.end() && p_it->second == masterPasswordHash;

    auto s_it = httplib::g_h_data.params.find("scope");
    bool scopeTest = s_it != httplib::g_h_data.params.end() && s_it->second == "api offline_access";

    auto ci_it = httplib::g_h_data.params.find("client_id");
    bool clientIdTest = ci_it != httplib::g_h_data.params.end() && ci_it->second == "desktop";

    auto dt_it = httplib::g_h_data.params.find("deviceType");
    bool deviceTypeTest = dt_it != httplib::g_h_data.params.end() && dt_it->second == "7";

    auto di_it = httplib::g_h_data.params.find("deviceIdentifier");
    bool deviceIdentifierTest = di_it != httplib::g_h_data.params.end() && !di_it->second.empty();

    auto dn_it = httplib::g_h_data.params.find("deviceName");
    bool deviceNameTest = dn_it != httplib::g_h_data.params.end() && dn_it->second == "firefox";

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(grantTypeTest);
    CHECK(usernameTest);
    CHECK(passwordTest);
    CHECK(scopeTest);
    CHECK(clientIdTest);
    CHECK(deviceTypeTest);
    CHECK(deviceNameTest);
    CHECK(deviceIdentifierTest);
}

TEST_CASE("getTokenWTotp Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string email = "email@a.com";
    std::string masterPasswordHash = "h@sh-d0nt-sh@r3-p1e@s3";
    std::string code = "co1d";

    std::optional<nlohmann::json> result = network.getTokenWTotp(email, masterPasswordHash, code);

    bool urlTest = httplib::g_h_data.url == "/identity/connect/token";
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();

    auto a_it = httplib::g_h_data.headers.find("Accept");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto c_it = httplib::g_h_data.headers.find("Content-Type");
    bool contentTest = (c_it != httplib::g_h_data.headers.end() && c_it->second == "application/x-www-form-urlencoded; charset=utf-8");

    auto g_it = httplib::g_h_data.params.find("grant_type");
    bool grantTypeTest = g_it != httplib::g_h_data.params.end() && g_it->second == "password";

    auto u_it = httplib::g_h_data.params.find("username");
    bool usernameTest = u_it != httplib::g_h_data.params.end() && u_it->second == email;

    auto p_it = httplib::g_h_data.params.find("password");
    bool passwordTest = p_it != httplib::g_h_data.params.end() && p_it->second == masterPasswordHash;

    auto s_it = httplib::g_h_data.params.find("scope");
    bool scopeTest = s_it != httplib::g_h_data.params.end() && s_it->second == "api offline_access";

    auto ci_it = httplib::g_h_data.params.find("client_id");
    bool clientIdTest = ci_it != httplib::g_h_data.params.end() && ci_it->second == "desktop";

    auto dt_it = httplib::g_h_data.params.find("deviceType");
    bool deviceTypeTest = dt_it != httplib::g_h_data.params.end() && dt_it->second == "7";

    auto di_it = httplib::g_h_data.params.find("deviceIdentifier");
    bool deviceIdentifierTest = di_it != httplib::g_h_data.params.end() && !di_it->second.empty();

    auto dn_it = httplib::g_h_data.params.find("deviceName");
    bool deviceNameTest = dn_it != httplib::g_h_data.params.end() && dn_it->second == "firefox";

    auto n_it = httplib::g_h_data.params.find("twoFactorToken");
    bool otpTest = n_it != httplib::g_h_data.params.end() && n_it->second == code;

    auto tf_it = httplib::g_h_data.params.find("twoFactorProvider");
    bool tfProviderTest = tf_it != httplib::g_h_data.params.end() && tf_it->second == "0";

    auto tfp_it = httplib::g_h_data.params.find("twoFactorRemember");
    bool tfRememberTest = tfp_it != httplib::g_h_data.params.end() && tfp_it->second == "0";

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(grantTypeTest);
    CHECK(usernameTest);
    CHECK(passwordTest);
    CHECK(scopeTest);
    CHECK(clientIdTest);
    CHECK(deviceTypeTest);
    CHECK(deviceNameTest);
    CHECK(deviceIdentifierTest);
    CHECK(otpTest);
    CHECK(tfProviderTest);
    CHECK(tfRememberTest);
}

TEST_CASE("getTokenWDeviceVerify Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string email = "email@a.com";
    std::string masterPasswordHash = "h@sh-d0nt-sh@r3-p1e@s3";
    std::string code = "co1d";

    std::optional<nlohmann::json> result = network.getTokenWDeviceVerify(email, masterPasswordHash, code);

    bool urlTest = httplib::g_h_data.url == "/identity/connect/token";
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();

    auto a_it = httplib::g_h_data.headers.find("Accept");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto c_it = httplib::g_h_data.headers.find("Content-Type");
    bool contentTest = (c_it != httplib::g_h_data.headers.end() && c_it->second == "application/x-www-form-urlencoded; charset=utf-8");

    auto g_it = httplib::g_h_data.params.find("grant_type");
    bool grantTypeTest = g_it != httplib::g_h_data.params.end() && g_it->second == "password";

    auto u_it = httplib::g_h_data.params.find("username");
    bool usernameTest = u_it != httplib::g_h_data.params.end() && u_it->second == email;

    auto p_it = httplib::g_h_data.params.find("password");
    bool passwordTest = p_it != httplib::g_h_data.params.end() && p_it->second == masterPasswordHash;

    auto s_it = httplib::g_h_data.params.find("scope");
    bool scopeTest = s_it != httplib::g_h_data.params.end() && s_it->second == "api offline_access";

    auto ci_it = httplib::g_h_data.params.find("client_id");
    bool clientIdTest = ci_it != httplib::g_h_data.params.end() && !ci_it->second.empty();

    auto dt_it = httplib::g_h_data.params.find("deviceType");
    bool deviceTypeTest = dt_it != httplib::g_h_data.params.end() && !dt_it->second.empty();

    auto di_it = httplib::g_h_data.params.find("deviceIdentifier");
    bool deviceIdentifierTest = di_it != httplib::g_h_data.params.end() && !di_it->second.empty();

    auto dn_it = httplib::g_h_data.params.find("deviceName");
    bool deviceNameTest = dn_it != httplib::g_h_data.params.end() && !dn_it->second.empty();

    auto n_it = httplib::g_h_data.params.find("newDeviceOtp");
    bool otpTest = n_it != httplib::g_h_data.params.end() && n_it->second == code;

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(grantTypeTest);
    CHECK(usernameTest);
    CHECK(passwordTest);
    CHECK(scopeTest);
    CHECK(clientIdTest);
    CHECK(deviceTypeTest);
    CHECK(deviceNameTest);
    CHECK(deviceIdentifierTest);
    CHECK(otpTest);
}

TEST_CASE("alive Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    bool result = network.checkConnectivity();

    bool urlTest = httplib::g_h_data.url == "/alive";

    REQUIRE(result);
    CHECK(urlTest);
}

TEST_CASE("accessToken Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";

    bool result = network.checkAccessTokenValidity(token);

    bool urlTest = httplib::g_h_data.url == "/api/accounts/profile";

    auto a_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == ("Bearer " + token));

    REQUIRE(result);
    CHECK(urlTest);
    CHECK(authTest);
}

TEST_CASE("getProfile Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";

    std::optional<nlohmann::json> result = network.getProfile(token);

    bool urlTest = httplib::g_h_data.url == "/api/accounts/profile";

    auto a_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(authTest);
}

TEST_CASE("refreshToken Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";

    std::optional<nlohmann::json> result = network.refreshToken(token);

    bool urlTest = httplib::g_h_data.url == "/identity/connect/token";
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();

    auto a_it = httplib::g_h_data.headers.find("Accept");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto c_it = httplib::g_h_data.headers.find("Content-Type");
    bool contentTest = (c_it != httplib::g_h_data.headers.end() && c_it->second == "application/x-www-form-urlencoded; charset=utf-8");

    auto g_it = httplib::g_h_data.params.find("grant_type");
    bool grantTypeTest = g_it != httplib::g_h_data.params.end() && g_it->second == "refresh_token";

    auto dt_it = httplib::g_h_data.params.find("deviceType");
    bool deviceTypeTest = dt_it != httplib::g_h_data.params.end() && !dt_it->second.empty();

    auto n_it = httplib::g_h_data.params.find("refresh_token");
    bool tokenTest = n_it != httplib::g_h_data.params.end() && n_it->second == token;

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(acceptTest);
    CHECK(contentTest);
    CHECK(grantTypeTest);
    CHECK(deviceTypeTest);
    CHECK(tokenTest);
}

TEST_CASE("getVault Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";

    std::optional<nlohmann::json> result = network.getVault(token);

    bool urlTest = httplib::g_h_data.url == "/api/sync";
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();

    auto a_it = httplib::g_h_data.headers.find("Accept");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(acceptTest);
    CHECK(authTest);
}

TEST_CASE("NewItem Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";
    nlohmann::json data;

    std::optional<nlohmann::json> result = network.NewItem(data, token);

    bool urlTest = httplib::g_h_data.url == "/api/ciphers";
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();
    bool contentTest = httplib::g_h_data.type == "application/json";

    auto a_it = httplib::g_h_data.headers.find("Content-Type");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(contentTest);
    CHECK(acceptTest);
    CHECK(authTest);
}

TEST_CASE("UpdateItem Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";
    nlohmann::json data;
    data["id"] = "CT5";

    std::optional<nlohmann::json> result = network.UpdateItem(data, token);

    bool urlTest = httplib::g_h_data.url == ("/api/ciphers/CT5");
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();
    bool contentTest = httplib::g_h_data.type == "application/json";

    auto a_it = httplib::g_h_data.headers.find("Content-Type");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(contentTest);
    CHECK(acceptTest);
    CHECK(authTest);
}

TEST_CASE("DeleteItem Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";
    std::string id = "CT5";

    std::optional<nlohmann::json> result = network.DeleteItem(id, token);

    bool urlTest = httplib::g_h_data.url == ("/api/ciphers/CT5");
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();

    auto a_it = httplib::g_h_data.headers.find("Content-Type");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(acceptTest);
    CHECK(authTest);
}

TEST_CASE("SoftDeleteItem Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";
    std::string id = "CT5";

    std::optional<nlohmann::json> result = network.SoftDeleteItem(id, token);

    bool urlTest = httplib::g_h_data.url == ("/api/ciphers/CT5/delete");
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();
    bool contentTest = httplib::g_h_data.type == "application/json";

    auto a_it = httplib::g_h_data.headers.find("Content-Type");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(contentTest);
    CHECK(acceptTest);
    CHECK(authTest);
}

TEST_CASE("RestoreItem Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";
    std::string id = "CT5";

    std::optional<nlohmann::json> result = network.RestoreItem(id, token);

    bool urlTest = httplib::g_h_data.url == ("/api/ciphers/CT5/restore");
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();
    bool contentTest = httplib::g_h_data.type == "application/json";

    auto a_it = httplib::g_h_data.headers.find("Content-Type");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(contentTest);
    CHECK(acceptTest);
    CHECK(authTest);
}

TEST_CASE("ArchiveItem Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";
    std::string id = "CT5";

    std::optional<nlohmann::json> result = network.ArchiveItem(id, token);

    bool urlTest = httplib::g_h_data.url == ("/api/ciphers/archive");
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();
    bool contentTest = httplib::g_h_data.type == "application/json";
    bool valueTest = nlohmann::json::accept(httplib::g_h_data.value);
    bool idValidTest = false;

    if (valueTest) {
        nlohmann::json p_value = nlohmann::json::parse(httplib::g_h_data.value);

        idValidTest = p_value.contains("ids")
            && p_value["ids"].is_array()
            && p_value["ids"].size() > 0
            && p_value["ids"][0].is_string()
            && p_value["ids"][0].get<std::string>() == "CT5";
    }

    auto a_it = httplib::g_h_data.headers.find("Content-Type");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(valueTest);
    CHECK(idValidTest);
    CHECK(contentTest);
    CHECK(acceptTest);
    CHECK(authTest);
}

TEST_CASE("ArchiveItem (multiple) Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";
    std::vector<std::string> ids;
    ids.push_back("CT5");
    ids.push_back("CT6");

    std::optional<nlohmann::json> result = network.ArchiveItem(ids, token);

    bool urlTest = httplib::g_h_data.url == ("/api/ciphers/archive");
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();
    bool contentTest = httplib::g_h_data.type == "application/json";
    bool valueTest = nlohmann::json::accept(httplib::g_h_data.value);
    bool idValidTest = false;

    if (valueTest) {
        nlohmann::json p_value = nlohmann::json::parse(httplib::g_h_data.value);

        idValidTest = p_value.contains("ids")
            && p_value["ids"].is_array()
            && p_value["ids"].size() > 0
            && p_value["ids"][0].is_string()
            && p_value["ids"][0].get<std::string>() == "CT5"
            && p_value["ids"][1].is_string()
            && p_value["ids"][1].get<std::string>() == "CT6";
    }

    auto a_it = httplib::g_h_data.headers.find("Content-Type");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(valueTest);
    CHECK(idValidTest);
    CHECK(contentTest);
    CHECK(acceptTest);
    CHECK(authTest);
}

TEST_CASE("UnArchiveItem Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";
    std::string id = "CT5";

    std::optional<nlohmann::json> result = network.UnArchiveItem(id, token);

    bool urlTest = httplib::g_h_data.url == ("/api/ciphers/unarchive");
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();
    bool contentTest = httplib::g_h_data.type == "application/json";
    bool valueTest = nlohmann::json::accept(httplib::g_h_data.value);
    bool idValidTest = false;

    if (valueTest) {
        nlohmann::json p_value = nlohmann::json::parse(httplib::g_h_data.value);

        idValidTest = p_value.contains("ids")
            && p_value["ids"].is_array()
            && p_value["ids"].size() > 0
            && p_value["ids"][0].is_string()
            && p_value["ids"][0].get<std::string>() == "CT5";
    }

    auto a_it = httplib::g_h_data.headers.find("Content-Type");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(valueTest);
    CHECK(idValidTest);
    CHECK(contentTest);
    CHECK(acceptTest);
    CHECK(authTest);
}

TEST_CASE("UnArchiveItem (multiple) Test") {
    ClientWarden::VaultNetwork network;

    network.initNetwork("a.com", "b.com", "c.com", "d.com");

    std::string token = "t0k3n";
    std::vector<std::string> ids;
    ids.push_back("CT5");
    ids.push_back("CT6");

    std::optional<nlohmann::json> result = network.UnArchiveItem(ids, token);

    bool urlTest = httplib::g_h_data.url == ("/api/ciphers/unarchive");
    bool bwClientNameTest = httplib::g_h_data.headers.find("bitwarden-client-name") != httplib::g_h_data.headers.end();
    bool bwClientVersionTest = httplib::g_h_data.headers.find("bitwarden-client-version") != httplib::g_h_data.headers.end();
    bool contentTest = httplib::g_h_data.type == "application/json";
    bool valueTest = nlohmann::json::accept(httplib::g_h_data.value);
    bool idValidTest = false;

    if (valueTest) {
        nlohmann::json p_value = nlohmann::json::parse(httplib::g_h_data.value);

        idValidTest = p_value.contains("ids")
            && p_value["ids"].is_array()
            && p_value["ids"].size() > 0
            && p_value["ids"][0].is_string()
            && p_value["ids"][0].get<std::string>() == "CT5"
            && p_value["ids"][1].is_string()
            && p_value["ids"][1].get<std::string>() == "CT6";
    }

    auto a_it = httplib::g_h_data.headers.find("Content-Type");
    bool acceptTest = (a_it != httplib::g_h_data.headers.end() && a_it->second == "application/json");

    auto au_it = httplib::g_h_data.headers.find("Authorization");
    bool authTest = (au_it != httplib::g_h_data.headers.end() && au_it->second == ("Bearer " + token));

    REQUIRE(result.has_value());
    CHECK(urlTest);
    CHECK(bwClientNameTest);
    CHECK(bwClientVersionTest);
    CHECK(valueTest);
    CHECK(idValidTest);
    CHECK(contentTest);
    CHECK(acceptTest);
    CHECK(authTest);
}