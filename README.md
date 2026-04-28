# ClientWarden
A Secure and Well Designed Alternative to the Desktop Bitwarden Client. Clientwarden uses WinUI for the Windows UI instead of Electron for efficiency and uses Botan for TOTP Codes, which will soon also be used for `secure_vector`'s and `secure_allocator`'s.
<img width="700" height="420" alt="image" src="https://github.com/user-attachments/assets/08a522ed-f4d3-4474-b52a-02db2e2fd51d" />

## Building
To build on Windows run:
```
mkdir build
conan install . --output-folder=build --build=missing
conan install . --output-folder=build --build=missing -s build_type=Debug
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=<VCPKG_PARENT>/vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows
cd ../
cmake --build build
```

## Credits
Thanks to:
 - [Fluent Icons](https://fluenticons.co/outlined/)
