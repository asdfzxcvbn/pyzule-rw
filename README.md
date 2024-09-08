# pyzule-rw / cyan

rewriting [pyzule](https://github.com/asdfzxcvbn/pyzule), but actually good this time! btw.. cyan/pyzule looks best with a monospace font !! :D

this is pretty much just a hobby project that i'll work on when i'm bored. pyzule in its current state is kinda ugly, but it works and i haven't really had the motivation to work on it. there really isn't any need for improvements, anyway..

`cyan` will ~~target python v3.12 (finally!)~~, be pep8-compliant (hopefully..), and be type-hinted!

## features

more coming soon! i'm trying to copy pyzule in order to deprecate it in favor of cyan, which is 1000x better

- inject deb, dylib, framework, bundle, and appex files/folders
- automatically fix dependencies on CydiaSubstrate **(cyan uses [ElleKit](https://github.com/evelyneee/ellekit/)!)**, Cephei*, and Orion
- copy any unknown file/folder types to app root
- remove UISupportedDevices
- remove watch app
- fakesign the output ipa/app
- thin all binaries to arm64, it can LARGELY reduce app size sometimes!
- remove all app extensions (or just encrypted ones!)

## install instructions

cyan works on linux, macOS, WSL, and jailbroken iOS!

first, make sure you have [ar](https://command-not-found.com/ar) and [tar](https://command-not-found.com/tar) installed

also obviously install python, version 3.9 or greater is required (the version available on the procursus repo for iOS)

**if you want to inject dylibs AND ARE NOT ON iOS,** make sure you install lief (you only have to do this once): `pip install -U lief`

then finally, to install or update cyan, just `pip install --force-reinstall git+https://github.com/asdfzxcvbn/pyzule-rw.git#egg=cyan`

## todo

[x] refactor: dont prepare, just copy and fix as you go

[x] feat: plist operations (-l and -r wont be implemented)

[x] feat: remove watch app

[x] feat: fakesign

[x] feat: thin binaries

[x] feat: plugin operations (-q, -e)

[] feat: .cyan files (lol rip .pyzule files)

