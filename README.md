# pyzule-rw / cyan

a rewrite of [pyzule](https://github.com/asdfzxcvbn/pyzule) that doesn't (completely) suck !!

cyan supports **linux, macOS, WSL, and jailbroken iOS!** all either x86_64 or arm64/aarch64 !!

## features

you can open an issue to request a feature :D !!

- generate and use shareable .cyan files to configure IPAs!
- inject deb, dylib, framework, bundle, and appex files/folders
- automatically fix dependencies on CydiaSubstrate **(cyan uses [ElleKit](https://github.com/evelyneee/ellekit/)!)**, Cephei*, and Orion
- copy any unknown file/folder types to app root
- change app name, version, bundle id, and minimum os version
- remove UISupportedDevices
- remove watch app
- change the app icon
- fakesign the output ipa/app
- thin all binaries to arm64, it can LARGELY reduce app size sometimes!
- remove all app extensions (or just encrypted ones!)

## install instructions

first, make sure you have [ar](https://command-not-found.com/ar) and [tar](https://command-not-found.com/tar) installed

also obviously install python, version 3.9 or greater is required (the version available on the procursus repo for iOS)

1. install [pipx](https://github.com/pypa/pipx?tab=readme-ov-file#install-pipx)
2. install cyan: `pipx install --force https://github.com/asdfzxcvbn/pyzule-rw/archive/main.zip`
3. follow any instructions `pipx` may have given you, like `pipx ensurepath`
4. **if you want to inject dylibs and ARE NOT ON iOS**: `pipx inject cyan lief`
5. **if you want to change app icons (iOS NOT supported)**: `pipx inject cyan Pillow`

to *update*, just run step 2 again !

## making cyan files

cyan comes bundled with the `cgen` command, which lets you generate `.cyan` files to pass to `-z`/`--cyan` !

## acknowledgements

- [Al4ise](https://github.com/Al4ise) for the original [Azule](https://github.com/Al4ise/Azule)
- [lief-project](https://github.com/lief-project) for [LIEF](https://github.com/lief-project/LIEF)

