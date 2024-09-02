import os
import sys
import shutil
import zipfile
import platform
import plistlib
from glob import glob
from argparse import Namespace
from typing import Optional, Any


def validate_inputs(args: Namespace) -> Optional[str]:
  if not (
      args.i.endswith(".ipa")
      or args.i.endswith(".app")
  ):
    return "the input file must be an ipa/app"

  if not os.path.exists(args.i):
    return f"{args.i} does not exist"

  if os.path.exists(args.o):
    if args.overwrite:
      return print("[*] output already exists; will overwrite !")

    try:
      overwrite = input(
        f"[<] {args.o} already exists, overwrite it? [Y/n] "
        if args.output is not None
        else "[<] no output was specified. overwrite the input? [Y/n] "
      ).strip().lower()
    except KeyboardInterrupt:
      sys.exit("[>] bye!")

    if overwrite not in ("y", "yes", ""):
      print("[>] quitting.")
      sys.exit(0)

  if args.f is not None:
    args.f = {os.path.normpath(f) for f in args.f}
    nonexistent = [f for f in args.f if not os.path.exists(f)]

    if len(nonexistent) != 0:
      print("[!] please ensure the following file(s) exist:")
      for ne in nonexistent:
        print(f"[?] - {ne}")
      sys.exit(1)


def get_app(path: str, tmpdir: str, is_ipa: bool) -> tuple[str, str]:
  payload = f"{tmpdir}/Payload"

  if is_ipa:
    print("[*] extracting ipa..")

    try:
      with zipfile.ZipFile(path) as ipa:
        names = ipa.namelist()

        if not any(name.startswith("Payload/") for name in names):
          raise KeyError
        elif not any(name.endswith(".app/Info.plist") for name in names):
          sys.exit("[!] no Info.plist, invalid app")

        ipa.extractall(tmpdir)
        app = glob(f"{payload}/*.app")[0]
        plist = f"{app}/Info.plist"
    except (KeyError, IndexError):
      sys.exit("[!] couldn't find either Payload or app folder, invalid ipa")
    except zipfile.BadZipFile:
      sys.exit(f"[!] {path} is not a zipfile (ipa)")

    print("[*] extracted ipa")
  else:
    if not os.path.isfile((plist := f"{path}/Info.plist")):
      sys.exit("[!] no Info.plist, invalid app")

    print("[*] copying app..")
    shutil.copytree(path, (app := f"{payload}/{os.path.basename(path)}"))
    print("[*] copied app")

  return app, plist


def get_tools_dir() -> str:
  mach = platform.machine()
  system = platform.system()
  prefix = ""

  if "iPhone" in mach or "iPad" in mach:
    mach = "arm64"
    prefix = "/var/jb"  # sorry, rootless only !!

  return f"{prefix}/opt/cyan/tools/{system}/{mach}"


def get_plist(path: str) -> dict[str, Any]:
  try:
    with open(path, "rb") as f:
      return plistlib.load(f)
  except Exception:
    sys.exit(f"[!] couldn't read {path}")

