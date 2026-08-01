# VaultWarden Spec
This is a simple document outlining how the Network Requests of VaultWarden work.

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
When entering an email, VaultWarden send a `POST` request to `https://<VWURL>/identity/accounts/prelogin/password` and returns a `200`.

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
After sending a prelogin request, it sends a `GET` request to `https://<VWURL>/api/devices/knowndevice` and returns a `200`. It provides no request data, and returns a response payload of `true` or `false`.