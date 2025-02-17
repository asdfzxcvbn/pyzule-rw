import os
import sys
import subprocess

from cyan import tbhutils


class Executable:
  install_dir, specific = tbhutils.get_tools_dir()
  nt = f"{specific}/install_name_tool"
  ldid = f"{specific}/ldid"
  lipo = f"{specific}/lipo"
  otool = f"{specific}/otool"
  idylib = f"{specific}/insert_dylib"

  # adding /usr/lib/ now, idk why i didnt before. lets hope nothing breaks
  ## LITERALLY 2 DAYS LATER. WHAT THE FUCK IS @LOADER_PATH HELP
  ## i will cry if only checking for '@' will break this.
  starters = ("\t/Library/", "\t/usr/lib/", "\t@")

  # substrate could show up as
  # CydiaSubstrate.framework, libsubstrate.dylib, EVEN CydiaSubstrate.dylib
  # AND PROBABLY EVEN MORE !!!! IT'S CRAZY.
  common = {
    "substrate.": {
      "name": "CydiaSubstrate.framework",
      "path": "@rpath/CydiaSubstrate.framework/CydiaSubstrate"
    },
    "orion.": {
      "name": "Orion.framework",
      "path": "@rpath/Orion.framework/Orion"
    },
    "cephei.": {
      "name": "Cephei.framework",
      "path": "@rpath/Cephei.framework/Cephei"
    },
    "cepheiui.": {
      "name": "CepheiUI.framework",
      "path": "@rpath/CepheiUI.framework/CepheiUI"
    },
    "cepheiprefs.": {
      "name": "CepheiPrefs.framework",
      "path": "@rpath/CepheiPrefs.framework/CepheiPrefs"
    }
  }

  def __init__(self, path: str):
    if not os.path.isfile(path):
      print(f"[!] {path} does not exist (executable)", file=sys.stderr)
      sys.exit(
        "[?] check the wiki for info: "
        "https://github.com/asdfzxcvbn/pyzule-rw/wiki/"
        "file-does-not-exist-(executable)-%3F"
      )

    self.path = path
    self.bn = os.path.basename(path)

  def is_encrypted(self) -> bool:
    proc = subprocess.run(
      [self.otool, "-l", self.path],
      capture_output=True
    )

    return b"cryptid 1" in proc.stdout

  def remove_signature(self) -> None:
    subprocess.run([self.ldid, "-R", self.path], stderr=subprocess.DEVNULL)

  def fakesign(self) -> bool:
    return subprocess.run([self.ldid, "-S", "-M", self.path]).returncode == 0

  def thin(self) -> bool:
    return subprocess.run(
      [self.lipo, "-thin", "arm64", self.path, "-output", self.path],
      stderr=subprocess.DEVNULL
    ).returncode == 0

  def change_dependency(self, old: str, new: str) -> None:
    subprocess.run(
      [self.nt, "-change", old, new, self.path],
      stderr=subprocess.DEVNULL
    )

  def fix_common_dependencies(self, needed: set[str]) -> None:
    self.remove_signature()

    for dep in self.get_dependencies():
      for common, info in self.common.items():
        if common in dep.lower():
          needed.add(common)

          if dep != info["path"]:
            self.change_dependency(dep, info["path"])
            print(
              f"[*] fixed common dependency in {self.bn}: "
              f"{dep} -> {info['path']}"
            )

  def fix_dependencies(self, tweaks: dict[str, str]) -> None:
    for dep in self.get_dependencies():
      for cname in tweaks:
        if cname in dep:
          # i wonder if there's a better way to do this?
          if cname.endswith(".framework"):
            # nah, not gonna parse the plist,
            # i've never seen a framework with a "mismatched" name
            npath = f"@rpath/{cname}/{cname[:-10]}"
          else:
            npath = f"@rpath/{cname}"

          if dep != npath:
            self.change_dependency(dep, npath)
            print(f"[*] fixed dependency in {self.bn}: {dep} -> {npath}")

  def get_dependencies(self) -> list[str]:
    proc = subprocess.run(
      [self.otool, "-L", self.path],
      capture_output=True, text=True
    )

    # split at [2:] to avoid otool's line and dylib's id
    tmp = proc.stdout.strip().split("\n")[2:]
    for ind, dep in enumerate(tmp):
      if "(architecture " in dep:  # avoid checking duplicate deps
        tmp = tmp[:ind]

    deps: list[str] = []
    for dep in tmp:
      if any(dep.startswith(s) for s in self.starters):
        deps.append(dep.split()[0])  # split() removes whitespace

    return deps

