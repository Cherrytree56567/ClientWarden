<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <!--<a href="https://github.com/Cherrytree56567/ClientWarden">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>-->

  <h3 align="center">ClientWarden</h3>

  <p align="center">
    A Secure and Well Designed Alternative to the Desktop Bitwarden Client. Clientwarden uses WinUI for the Windows UI instead of Electron for efficiency and uses Botan for TOTP Codes, which will soon also be used for `secure_vector`'s and `secure_allocator`'s. Currently only Logins are clickable in the Clientwarden UI and only Username, Password's and Websites are able to be displayed.
    <br />
    <br />
    <a href="https://github.com/Cherrytree56567/ClientWarden/issues/new?labels=bug&template=bug-report---.md">Report Bug</a>
    &middot;
    <a href="https://github.com/Cherrytree56567/ClientWarden/issues/new?labels=enhancement&template=feature-request---.md">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li> 
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](https://github.com/Cherrytree56567/ClientWarden)

While the Bitwarden Web Client looks ok, the desktop Bitwarden Client doesn't look very good and uses lots of memory, mainly due to electron. There are different Password Managers like 1Pass which do use Electron, but have an appealing UI. My main inspiration is 1Password because it looks the best out of all the major (non Open Source) Password Managers (LastPass, Bitwarden and 1Pass). The main goal is to make an effecient, safe and appealing Password Manager based on Bitwarden.

Anyways, here are some reasons to use Clientwarden:
* Clientwarden uses WinUI to blend in with Windows and look as good as possible
* Clientwarden uses Botan secure_vector's for storing passwords safely (still being impl'd)
* Clientwarden avoids using too much memory

### Built With

* Botan - [![Conan Center](https://img.shields.io/conan/v/botan)](https://conan.io/center/recipes/botan)
* SPDLog - [![Conan Center](https://img.shields.io/conan/v/spdlog)](https://conan.io/center/recipes/spdlog)
* OpenSSL - [![Conan Center](https://img.shields.io/conan/v/openssl)](https://conan.io/center/recipes/openssl)
* Nlohmann JSON - [![Conan Center](https://img.shields.io/conan/v/nlohmann_json)](https://conan.io/center/recipes/nlohmann_json)
* CPP HTTPLib - [![Conan Center](https://img.shields.io/conan/v/cpp-httplib)](https://conan.io/center/recipes/cpp-httplib)
* Boost - [![Conan Center](https://img.shields.io/conan/v/boost)](https://conan.io/center/recipes/boost)

<!-- GETTING STARTED -->
## Getting Started

Here are some instructions on how to build Clientwarden, currently only on windows pc's.

### Prerequisites

Before building Clientwarden, install VS 2026 with C++ and WinUI Extensions, CMake, Conan, vcpkg and git.
```sh
mkdir build
conan install . --output-folder=build --build=missing
conan install . --output-folder=build --build=missing -s build_type=Debug
```
You might need to use the `-s compiler.cppstd=20` flag.

### Building

1. Install CMake
2. Clone the repo
   ```sh
   git clone https://github.com/Cherrytree56567/ClientWarden.git
   ```
3. Prerequisites
4. Build
   ```sh
   cd build
   cmake .. -DCMAKE_TOOLCHAIN_FILE=build/Debug/generators/conan_toolchain.cmake
   cd ../
   cmake --build build
   ```
5. Enjoy!

### Building XCode (Mac OS Only)

1. Install CMake
2. Clone the repo
   ```sh
   git clone https://github.com/Cherrytree56567/ClientWarden.git
   ```
3. Prerequisites
4. Build
   ```sh
   cd build
   cmake .. -DCMAKE_TOOLCHAIN_FILE=build/Debug/generators/conan_toolchain.cmake -G Xcode
   cd ../
   cmake --build build
   ```
5. Enjoy!

<!-- ROADMAP -->
## Roadmap

- [X] MacOS Support
    - [X] Attachment Support
    - [X] Bin Page
    - [X] Settings Support
    - [X] Lock Support
    - [X] UI Bridge
      - [X] Nav Panel Bridge
      - [X] Items Panel Bridge
      - [X] Side Panel Bridge
        - [X] Save Support
      - [X] Settings Bridge
        - [X] Add ScreenShot Option
    - [X] Add Errors on Bridge
    - [X] Fix Login Crashes
    - [X] Fix Freezing Issue
    - [X] Fix Vault Signouts
    - [X] Code Review
    - [X] Show Deletion Date
    - [X] Show Password History Date
    - [X] Reprompt Support
    - [X] Add Reprompt Toggle
    - [X] Add Password Generator
    - [X] Highlight selected item
    - [X] Add Animation for extending window
    - [ ] Folder Tree View
    - [ ] Passkey Support
- [X] Derive Item Classes from Generic Item
- [ ] Windows Support
    - [ ] Create Nav Panel
    - [ ] Create Side Panel
    - [ ] Create Create Items Panel
    - [ ] Settings Support
    - [ ] UI Bridge
    - [ ] Passkey Support
- [ ] Linux Support
    - [ ] Create Nav Panel
    - [ ] Create Side Panel
    - [ ] Create Create Items Panel
    - [ ] Settings Support
    - [ ] UI Bridge
    - [ ] Passkey Support
- [ ] Official Release
- [ ] Watchtower
- [ ] Custom Item Types
- [ ] iOS and Android Support

See the [open issues](https://github.com/Cherrytree56567/Clientwarden/issues) for a full list of proposed features (and known issues).

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Top contributors:

<a href="https://github.com/Cherrytree56567/ClientWarden/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Cherrytree56567/ClientWarden" alt="contrib.rocks image" />
</a>

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<!-- CONTACT -->
## Contact

Use the Discussion Page for Contact

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

Thanks to:

* [Fluent Icons](https://fluenticons.co/outlined/)
* [Readme Template](https://github.com/othneildrew/Best-README-Template)
* @Dexrn - For helping me with base and derived classes in the Backend

[contributors-shield]: https://img.shields.io/github/contributors/Cherrytree56567/ClientWarden.svg?style=for-the-badge
[contributors-url]: https://github.com/Cherrytree56567/ClientWarden/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/Cherrytree56567/ClientWarden.svg?style=for-the-badge
[forks-url]: https://github.com/Cherrytree56567/ClientWarden/network/members
[stars-shield]: https://img.shields.io/github/stars/Cherrytree56567/ClientWarden.svg?style=for-the-badge
[stars-url]: https://github.com/Cherrytree56567/ClientWarden/stargazers
[issues-shield]: https://img.shields.io/github/issues/Cherrytree56567/ClientWarden.svg?style=for-the-badge
[issues-url]: https://github.com/Cherrytree56567/ClientWarden/issues
[license-shield]: https://img.shields.io/github/license/Cherrytree56567/ClientWarden.svg?style=for-the-badge
[license-url]: https://github.com/Cherrytree56567/ClientWarden/blob/master/LICENSE
[product-screenshot]: https://github.com/user-attachments/assets/c0ccc0d1-e9eb-4bd9-8f78-6ec42e79e365
