import os
import sys
import subprocess
from typing import Optional

try:
  import lief
except Exception:
  pass

from cyan import tbhutils


class Executable:
  install_dir, specific = tbhutils.get_tools_dir()
  nt = f"{specific}/install_name_tool"
  ldid = f"{specific}/ldid"
  lipo = f"{specific}/lipo"
  otool = f"{specific}/otool"
  idylib = f"{specific}/insert_dylib"

  starters = ("\t/Library/", "\t@rpath", "\t@executable_path")
  common = {
    # substrate could show up as
    # CydiaSubstrate.framework, libsubstrate.dylib, EVEN CydiaSubstrate.dylib
    # AND PROBABLY EVEN MORE !!!! IT'S CRAZY.

    "CydiaSubstrate.framework": "CydiaSubstrate.framework",
    "Orion.framework": "Orion.framework",
    "Cephei.framework": "Cephei.framework",
    "CepheiUI.framework": "CepheiUI.framework",
    "CepheiPrefs.framework": "CepheiPrefs.framework"
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
    self.inj: Optional = None  # type: ignore

    if os.path.isfile(self.idylib):
      self.inj_func = self.idyl_inject
    else:
      self.inj_func = self.lief_inject

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

  def lief_inject(self, cmd: str) -> None:
    if self.inj is None:  # type: ignore
      try:
        lief.logging.disable()  # type: ignore
      except Exception:
        sys.exit("[!] did you forget to install lief?")

      self.inj = lief.parse(self.path)  # type: ignore

    try:
      self.inj.add(lief.MachO.DylibCommand.weak_lib(cmd))  # type: ignore
    except AttributeError:
      sys.exit("[!] couldn't add LC (lief), did you use a valid app?")

  def idyl_inject(self, cmd: str) -> None:
    proc = subprocess.run(
      [
        self.idylib, "--weak", "--inplace", "--strip-codesig", "--all-yes",
        cmd, self.path
      ], capture_output=True, text=True
    )

    if proc.returncode != 0:
      sys.exit(f"[!] couldn't add LC (insert_dylib), error:\n{proc.stderr}")

  def fix_dependencies(self, tweaks: dict[str, str], need: set[str]) -> None:
    self.remove_signature()

    for dep in self.get_dependencies():
      for cname in (tweaks | self.common):
        if cname in dep:
          # i wonder if there's a better way to do this?
          if cname.endswith(".framework"):
            npath = f"@rpath/{cname}/{cname[:-10]}"
          else:
            npath = f"@rpath/{cname}"

          if dep != npath:
            self.change_dependency(dep, npath)
            print(f"[*] fixed dependency in {self.bn}: {dep} -> {npath}")

          if cname in self.common:
            need.add(cname)

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

