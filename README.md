# pyzule-rw / cyan

a rewrite of [pyzule](https://github.com/asdfzxcvbn/pyzule) that doesn't (completely) suck !!

cyan supports **linux, macOS, WSL, and jailbroken iOS!** all either x86_64 or arm64/aarch64 !!

## features

you can open an issue to request a feature :D !!

- generate and use [shareable .cyan files](https://github.com/asdfzxcvbn/cyan-gen) to configure IPAs!
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

**if you want to inject dylibs AND ARE NOT ON iOS,** make sure you install lief (you only have to do this once): `pip install -U lief`

**if you want to change app icons (iOS NOT supported),** also make sure you install pillow: `pip install Pillow`

then finally, to install or update cyan, just `pip install --force-reinstall git+https://github.com/asdfzxcvbn/pyzule-rw.git#egg=cyan`

## acknowledgements

- [Al4ise](https://github.com/Al4ise) for the original [Azule](https://github.com/Al4ise/Azule)
- [lief-project](https://github.com/lief-project) for [LIEF](https://github.com/lief-project/LIEF)

### todo

[x] refactor: dont prepare, just copy and fix as you go

[x] feat: plist operations (-l and -r wont be implemented)

[x] feat: remove watch app

[x] feat: fakesign

[x] feat: thin binaries

[x] feat: plugin operations (-q, -e)

[x] feat: change app icon

[x] feat: .cyan files (lol rip .pyzule files)

:D

