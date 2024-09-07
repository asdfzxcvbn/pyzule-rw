import os
import sys
import shutil
import zipfile
import platform
import subprocess
from uuid import uuid4
from typing import Optional
from glob import glob, iglob
from argparse import Namespace


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
    # dictionary ensures unique names
    args.f = {os.path.basename(f): os.path.normpath(f) for f in args.f}
    nonexistent = [f for f in args.f.values() if not os.path.exists(f)]

    if len(nonexistent) != 0:
      print("[!] please ensure the following file(s) exist:")
      for ne in nonexistent:
        print(f"[?] - {ne}")
      sys.exit(1)


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

  return (
    install_dir,
    f"{install_dir}/tools/{system}/{mach}"
  )


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
      glob(f"{t2}/**/*.bundle", recursive=True),
      glob(f"{t2}/**/*.appex", recursive=True),
      glob(f"{t2}/**/*.framework", recursive=True)
  ), []):  # type: ignore
    if os.path.islink(hi):
      continue  # symlinks are broken iirc

    tweaks[os.path.basename(hi)] = hi

  print(f"[*] extracted {os.path.basename(deb)}")
  del tweaks[os.path.basename(deb)]


def make_ipa(tmpdir: str, output: str, level: int) -> None:
  # ensure names are written as Payload/...
  os.chdir(tmpdir)
  weird = 0

  with zipfile.ZipFile(
      output, "w", zipfile.ZIP_DEFLATED, compresslevel=level
  ) as zf:
    for f in iglob("Payload/**", recursive=True):
      try:
        zf.write(f)
      except ValueError:
        weird += 1

  if weird != 0:
    print(f"[?] was unable to zip {weird} files due to timestamps")

