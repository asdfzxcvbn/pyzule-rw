import os
import sys
import json
import shutil
import zipfile
import platform
import subprocess
from uuid import uuid4
from glob import glob, iglob
from argparse import Namespace
from typing import Optional, Any
from plistlib import load as pload

HAS_ZIP = shutil.which("zip") is not None
HAS_UNZIP = shutil.which("unzip") is not None


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
      print(f"[*] {args.o} already exists; overwriting")
    else:
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
    new: dict[str, str] = {}  # dictionary ensures unique names

    for f in list(args.f):
      if f[-1] == "/":  # yeah this is stupid
        f = f[:-1]

      if not os.path.exists(f):
        sys.exit(f"[!] \"{f}\" does not exist")

      new[os.path.basename(f)] = os.path.realpath(f)

    # i would've modified args.f directly, but it causes type-hinting error :(
    args.f = new

  if (
      args.m is not None
      and any(char not in "0123456789." for char in args.m)
  ):
    sys.exit(f"[!] invalid OS version: {args.m}")

  if args.k is not None and not os.path.isfile(args.k):
    sys.exit(f"[!] {args.k} does not exist")

  if args.cyan is not None and not os.path.isfile(args.cyan):
    sys.exit(f"[!] {args.cyan} does not exist")

  if args.x is not None:
    if not os.path.isfile(args.x):
      sys.exit(f"[!] {args.x} does not exist")

    try:
      with open(args.x, "rb") as f:
        args.x = pload(f)
    except Exception:
      sys.exit("[!] couldn't parse given entitlements file")


def get_app(path: str, tmpdir: str, is_ipa: bool) -> str:
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

        # using unzip fixes extraction errors in ipas with chinese chars, etc
        if HAS_UNZIP:
          subprocess.run(
            ["unzip", path, "-d", tmpdir],
            stdout=subprocess.DEVNULL
          )
        else:
          ipa.extractall(tmpdir)

        app = glob(f"{payload}/*.app")[0]
    except (KeyError, IndexError):
      sys.exit("[!] couldn't find either Payload or app folder, invalid ipa")
    except zipfile.BadZipFile:
      sys.exit(f"[!] {path} is not a zipfile (ipa)")

    print("[*] extracted ipa")
  else:
    if not os.path.isfile(f"{path}/Info.plist"):
      sys.exit("[!] no Info.plist, invalid app")

    print("[*] copying app..")
    shutil.copytree(path, (app := f"{payload}/{os.path.basename(path)}"))
    print("[*] copied app")

  return app


def get_tools_dir() -> tuple[str, str]:
  mach = platform.machine()
  system = platform.system()

  if "iPhone" in mach or "iPad" in mach:
    mach = "iOS"

  # thank god i dont have to use importlib,
  # it's the WORST standard library package prior to 3.12
  install_dir = os.path.dirname(__file__)
  specific_dir = f"{install_dir}/tools/{system}/{mach}"

  if not os.path.isdir(specific_dir):
    sys.exit(f"[!] cyan is not supported on: {system} {mach}")

  return (install_dir, specific_dir)


def delete_if_exists(path: str, bn: str) -> bool:
  is_file = os.path.isfile(path)

  try:
    if is_file:
      os.remove(path)
    else:
      shutil.rmtree(path)

    print(f"[?] {bn} already existed, replacing")
    return True
  except FileNotFoundError:
    return False


# damn it, literally EVERY FUCKING python version before 3.12 FUCKING SUCKS
# no `delete` in `TemporaryDirectory` ?! GREAT !!!
def extract_deb(deb: str, tweaks: dict[str, str], tmpdir: str) -> None:
  t2 = f"{tmpdir}/{uuid4()}"
  os.mkdir(t2)

  if platform.system() == "Linux":
    tool = ["ar", "-x", deb, f"--output={t2}"]
  elif "iPhone" in platform.machine() or "iPad" in platform.machine():
    os.chdir(t2)  # BAHAHAHAHHAHA.
    tool = ["ar", "-x", deb]
  else:
    tool = ["tar", "-xf", deb, f"--directory={t2}"]

  try:
    subprocess.run(tool, check=True)
  except Exception:
    sys.exit(f"[!] couldn't extract {os.path.basename(deb)}")

  # it's not always "data.tar.gz"
  data_tar = glob(f"{t2}/data.*")[0]
  subprocess.run(["tar", "-xf", data_tar, f"--directory={t2}"])

  for hi in sum((
      glob(f"{t2}/**/*.dylib", recursive=True),
      glob(f"{t2}/**/*.appex", recursive=True),
      glob(f"{t2}/**/*.bundle", recursive=True),
      glob(f"{t2}/**/*.framework", recursive=True)
  ), []):  # type: ignore
    if (
        os.path.islink(hi)  # symlinks are broken iirc
        or hi.count(".bundle") > 1  # prevent sub-bundle detection (rip)
        or hi.count(".framework") > 1
    ):
      continue

    tweaks[os.path.basename(hi)] = hi

  print(f"[*] extracted {os.path.basename(deb)}")
  del tweaks[os.path.basename(deb)]


def make_ipa(tmpdir: str, output: str, level: int) -> None:
  # ensure names are written as Payload/...
  os.chdir(tmpdir)
  weird = 0

  if HAS_ZIP:
    try:
      os.remove(output)  # zip command updates zipfiles by default
    except FileNotFoundError:
      pass

    subprocess.run(
      ["zip", f"-{level}", "-r", output, "Payload"],
      stdout=subprocess.DEVNULL
    )
  else:
    with zipfile.ZipFile(
        output, "w", zipfile.ZIP_DEFLATED, compresslevel=level
    ) as zf:
      for f in iglob("Payload/**", recursive=True):
        try:
          zf.write(f)
        except ValueError:
          weird += 1

  if weird != 0:
    print(f"[?] was unable to zip {weird} file(s) due to timestamps")


def parse_cyan(args: dict[str, Any], tmpdir: str) -> None:
  print("[*] parsing .cyan file..")
  with zipfile.ZipFile(args["cyan"]) as zf:
    DOT_PATH = f"{tmpdir}/cyan"
    os.mkdir(DOT_PATH)

    with zf.open("config.json") as f:
      config = json.load(f)

    if "f" in config:
      NAMES = [n for n in zf.namelist() if n.startswith("inject/")]
      zf.extractall(DOT_PATH, NAMES)

      # ensure not None
      args["f"] = args["f"] if args["f"] is not None else {}
      for e in os.scandir(f"{DOT_PATH}/inject"):
        args["f"][e.name] = e.path
      del config["f"]
    if "k" in config:
      args["k"] = zf.extract("icon.idk", DOT_PATH)
      del config["k"]

    for k, v in config.items():
      args[k] = v

