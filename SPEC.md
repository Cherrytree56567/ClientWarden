# VaultWarden Spec
This is a simple document outlining how the Network Requests of VaultWarden work.

# VaultWarden vs Bitwarden
TODO

## Sending Requests
BitWarden has 5 different URL's for different purposes, the Main URL, the API URL, the Vault URL, the Icon URL and the WebSocket URL. The Main URL is usually the main page, like `https://bitwarden.com`, whereas the API URL is used checking connectivity via an `alive` endpoint. The Vault URL is used for Vault operations, like creating a new item, or logging in to an account. The WebSocket URL is used to live sync ciphers and other stuff. Usually, vaultwarden has the same main, api and vault url, but still uses the bitwarden icon server. The main url for bitwarden is `https://bitwarden.com` and the api url is `https://api.bitwarden.com` and the vault url is `https://vault.bitwarden.com`.
> NOTE
> If you don't use a proper useragent or don't specify the correct request headers, bitwarden/vaultwarden may fail and provide you with wrong info. A common example is when bitwarden sends you the wrong kdf count.

Bitwarden and Vaultwarden require a *proper* useragent, device type, content type, client name and client version.
Here is an example:
```
await fetch("https://<VW URL>/identity/accounts/prelogin/password", {
    "credentials": "omit",
    "headers": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:153.0) Gecko/20100101 Firefox/153.0",
        "Accept": "application/json",
        ...
        "content-type": "application/json; charset=utf-8",
        ...
        "device-type": "10",
        "is-prerelease": "1",
        "Bitwarden-Client-Name": "web",
        "Bitwarden-Client-Version": "2026.4.1",
        "authorization": "Bearer XXX",
        ...
    },
    ...
});
```
Bitwarden supports `web` and `desktop` for the `Bitwarden-Client-Name`.
<br>
For `device-type`, Bitwarden uses the following values for different devices:
```
 - Android = 0
 - iOS = 1
 - Chrome Extension = 2
 - Firefox Extension = 3
 - Opera Extension = 4
 - Edge Extension = 5
 - Windows Desktop = 6
 - MacOS Desktop = 7
 - Linux Desktop = 8
 - Chrome = 9
 - Firefox = 10
 - Opera = 11
 - Edge = 12
 - Internet Explorer = 13
 - Unknown Browser = 14
 - Android Amazon = 15
 - UWP = 16
 - Safari Browser = 17
 - Vivaldi Browser = 18
 - Vivaldi Extension = 19
 - Safari Extension = 20
 - SDK = 21
 - Server = 22
 - Windows CLI = 23
 - MacOS CLI = 24
 - Linux CLI = 25
 - DuckDuckGo = 26
```

## Logging In
When entering an email, VaultWarden send a `POST` JSON request to `https://<VWURL>/identity/accounts/prelogin/password` and returns a `200`.
<br>
When sending the `POST` request, it sends a request JSON:
```
{
    "email":"a@a.com"
}
```
and returns a JSON response:
```
{
    "kdf":0,
    "kdfIterations":600001,
    "kdfMemory":null,
    "kdfParallelism":null
}
```
After sending a prelogin request, it sends a `GET` JSON request to `https://<VWURL>/api/devices/knowndevice` and returns a `200`. It provides no request data, and returns a response payload of `true` or `false`.

> Note
> Prelogin and KnownDevice requests both require a `device-identifier` GUID passed from the request headers.

After entering a password, it sends a `POST` request to `https://<VWURL>/identity/connect/token` with the `application/x-www-form-urlencoded; charset=utf-8` content type header and returns a `200`.
<br>
It Requests: 
```
scope	"api offline_access"
client_id	"web"
deviceType	"10"
deviceIdentifier	"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
deviceName	"firefox"
twoFactorToken	"XXXXXX"
twoFactorProvider	"5"
twoFactorRemember	"0"
grant_type	"password"
username	"XXXX"
password	"XXXX"
```
And gets a JSON response:
```
{
    "AccountKeys": {
        "Object": "privateKeys",
        "publicKeyEncryptionKeyPair": {
            "Object": "publicKeyEncryptionKeyPair",
            "publicKey": "XXXX"
        }
    },
    "ForcePasswordReset": false,
    "Kdf": 0,
    "KdfIterations": 600001,
    "KdfMemory": null,
    "KdfParallelism": null,
    "Key": "XXXX",
    "MasterPasswordPolicy": {
        "Object": "masterPasswordPolicy"
    },
    "PrivateKey": "XXXX",
    "ResetMasterPassword": false,
    "UserDecryptionOptions": {
        "HasMasterPassword": true,
        "MasterPasswordUnlock": {
            "Kdf": {
                "Iterations": 600001,
                "KdfType": 0,
                "Memory": null,
                "Parallelism": null
            },
            "MasterKeyEncryptedUserKey": "XXXX",
            "MasterKeyWrappedUserKey": "XXXX",
            "Salt": "XXXX"
        },
        "Object": "userDecryptionOptions"
    },
    "access_token": "XXXX",
    "expires_in": 7200,
    "refresh_token": "XXXX",
    "scope": "api offline_access",
    "token_type": "Bearer"
}
```
It then sends a `GET` request to `https://<VWURL>/api/config` and returns `200`, along with a JSON respose:
```
{
    "environment": {
        "api": "https://<VWURL>/api",
        "cloudRegion": null,
        "identity": "https://<VWURL>/identity",
        "notifications": "https://<VWURL>/notifications",
        "sso": "",
        "vault": "https://<VWURL>"
    },
    "featureStates": {
        "pm-19148-innovation-archive": true
    },
    "gitHash": "f21a3ada",
    "object": "config",
    "push": {
        "pushTechnology": 0,
        "vapidPublicKey": null
    },
    "server": {
        "name": "Vaultwarden",
        "url": "https://github.com/dani-garcia/vaultwarden"
    },
    "settings": {
        "disableUserRegistration": false
    },
    "version": "2025.12.0"
}
```

## Syncing
After logging in or unlocking the Vault, it tends to sync with the server.
It sends a `GET` request to `https://<VWURL>/api/sync?excludeDomains=true`