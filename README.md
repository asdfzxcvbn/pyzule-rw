# pyzule-rw / cyan

rewriting [pyzule](https://github.com/asdfzxcvbn/pyzule), but actually good this time! btw.. cyan/pyzule looks best with a monospace font !! :D

this is pretty much just a hobby project that i'll work on when i'm bored. pyzule in its current state is kinda ugly, but it works and i haven't really had the motivation to work on it. there really isn't any need for improvements, anyway..

`cyan` will ~~target python v3.12 (finally!)~~, be pep8-compliant (hopefully..), and be type-hinted!

## features

more coming soon! i'm trying to copy pyzule in order to deprecate it in favor of cyan, which is 1000x better

- inject deb, dylib, framework, bundle, and appex files/folders
- automatically fix dependencies on CydiaSubstrate (cyan uses ElleKit!), Cephei*, and Orion
- copy any unknown file/folder types to app root
- remove UISupportedDevices
- remove watch app
- fakesign the output ipa/app
- thin all binaries to arm64, it can LARGELY reduce app size sometimes!

## notes

cyan is pretty much "v1.0" now i guess. injection works and is stable, and iOS (should..) have all the right fixes for running cyan, however a bug in python3.9 from procursus prevents it from running.

so to reaffirm this, **iOS is currently not supported until an updated python for iOS gets released**

**if you want to inject dylibs,** make sure you install lief (you only have to do this once): `pip install -U lief`

to install or update cyan, just `pip install --force-reinstall git+https://github.com/asdfzxcvbn/pyzule-rw.git#egg=cyan`

## todo

[] refactor: dont prepare, just copy and fix as you go

[2] feat: plist operations (-n, -v, -b, -m, -l, -r)

[x] feat: remove watch app

[x] feat: fakesign

[] feat: thin binaries

[] feat: plugin operations (-q, -e)

[] feat: .cyan files (lol rip .pyzule files)

