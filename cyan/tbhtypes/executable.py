import os
import sys
import shutil
import subprocess
from typing import Optional

import lief

from cyan import tbhutils


class Executable:
  install_dir, specific = tbhutils.get_tools_dir()
  nt = f"{specific}/install_name_tool"
  ldid = f"{specific}/ldid"
  otool = f"{specific}/otool"

  starters = ("\t/Library/", "\t@rpath", "\t@executable_path")

  def __init__(self, path: str, bundle_path: Optional[str] = None):
    if not os.path.isfile(path):
      sys.exit(f"[!] {path} does not exist (executable)")

    self.path = path
    self.bundle_path = bundle_path

    self.bn = os.path.basename(path)
    self.inj: Optional[lief.MachO.Binary] = None

    if self.specific.endswith("iOS"):
      self.inj_func = self.ios_inject
    else:
      self.inj_func = self.insert_cmd

  def is_encrypted(self) -> bool:
    proc = subprocess.run(
      [self.otool, "-l", self.path],
      capture_output=True
    )

    return b"cryptid 1" in proc.stdout

  def inject(self, tweaks: dict[str, str], tmpdir: str) -> None:
    # we only inject into the main executable
    assert self.bundle_path is not None

    has_entitlements = False
    ENT_PATH = f"{self.bundle_path}/cyan.entitlements"
    PLUGINS_DIR = f"{self.bundle_path}/PlugIns"
    FRAMEWORKS_DIR = f"{self.bundle_path}/Frameworks"

    with open(ENT_PATH, "wb") as entf:
      proc = subprocess.run(
        [self.ldid, "-e", self.path],
        capture_output=True
      )

      entf.write(proc.stdout)

    if os.path.getsize(ENT_PATH) > 0:
      has_entitlements = True

    # iirc, injecting doesnt work (sometimes) if the file isn't signed
    self.fakesign(False)

    if any(t.endswith(".appex") for t in tweaks):
      os.makedirs(PLUGINS_DIR, exist_ok=True)

    if any(
        t.endswith(k)
        for t in tweaks
        for k in (".deb", ".dylib", ".framework")
    ):
      os.makedirs(FRAMEWORKS_DIR, exist_ok=True)

      # some apps really dont have this lol
      subprocess.run(
        [self.nt, "-add_rpath", "@executable_path/Frameworks", self.path],
        stderr=subprocess.DEVNULL
      )

    # need ~~two~~ THREE loops, one for copying all files to tmpdir
    print("[*] preparing; this may take a while, sorry")
    for bn, path in dict(tweaks).items():
      if bn.endswith(".deb"):
        tbhutils.extract_deb(path, tweaks, tmpdir)
        continue

      try:
        tweaks[bn] = shutil.copytree(path, f"{tmpdir}/{bn}")
      except NotADirectoryError:
        tweaks[bn] = shutil.copy2(path, tmpdir)

      # print(f"[*] prepared {bn}")

    needed: set[str] = set()
    common = {
      # substrate could show up as
      # CydiaSubstrate.framework, libsubstrate.dylib, CydiaSubstrate.dylib
      # and probably even more. it's crazy.

      "ubstrate.": "CydiaSubstrate",
      "Orion.framework": "Orion",
      "Cephei.framework": "Cephei",
      "CepheiUI.framework": "CepheiUI",
      "CepheiPrefs.framework": "CepheiPrefs"
    }

    # another loop for fixing dylib dependencies
    for dbn, path in tweaks.items():
      if not dbn.endswith(".dylib"):
        continue

      dylib = Executable(path)
      dylib.fakesign()

      # fix dependencies
      for dep in dylib.get_dependencies():
        for cname in (common | tweaks):
          if cname in dep:
            if cname.endswith(".framework"):
              npath = f"@rpath/{cname}/{cname[:-10]}"
            else:
              npath = f"@rpath/{cname}"

            self.change_dependency(dep, npath)
            if cname in common:
              needed.add(cname)

            # avoid printing that we "fixed" something to itself lol
            if dep != npath:
              print(f"[*] fixed dependency in {dbn}: {dep} -> {npath}")

    ## "sub"-loop, just adding the needed common deps
    if "ubstrate." in needed:
      del common["ubstrate."]  # lol rip
      common["CydiaSubstrate.framework"] = "CydiaSubstrate"

      needed.remove("ubstrate.")
      needed.add("CydiaSubstrate.framework")

    if "Orion.framework" in needed:
      needed.add("CydiaSubstrate.framework")

    for missing in needed:
      ip = f"{FRAMEWORKS_DIR}/{missing}"
      existed = tbhutils.delete_if_exists(ip, missing)
      shutil.copytree(f"{self.install_dir}/extras/{missing}", ip)

      if not existed:
        print(f"[*] auto-injected {missing}")

    # and FINALLY, one for actually injecting
    for bn, path in tweaks.items():
      if bn.endswith(".appex"):
        fpath = f"{PLUGINS_DIR}/{bn}"
        existed = tbhutils.delete_if_exists(fpath, bn)
        shutil.copytree(path, fpath)
      elif bn.endswith(".dylib"):
        fpath = f"{FRAMEWORKS_DIR}/{bn}"
        existed = tbhutils.delete_if_exists(fpath, bn)
        self.inj_func(f"@rpath/{bn}")
        shutil.copy2(path, FRAMEWORKS_DIR)
      elif bn.endswith(".framework"):
        fpath = f"{FRAMEWORKS_DIR}/{bn}"
        existed = tbhutils.delete_if_exists(fpath, bn)
        self.inj_func(f"@rpath/{bn}/{bn[:-10]}")
        shutil.copytree(path, fpath)
      else:
        fpath = f"{self.bundle_path}/{bn}"
        existed = tbhutils.delete_if_exists(fpath, bn)
        try:
          shutil.copytree(path, fpath)
        except NotADirectoryError:
          shutil.copy2(path, self.bundle_path)

      if not existed:
        print(f"[*] injected {bn}")

    # FINALLY !!
    if self.inj is not None:
      self.inj.write(self.path)

    if has_entitlements:
      subprocess.run(["ldid", f"-S{ENT_PATH}", self.path])
      print("[*] restored entitlements")

  def fakesign(self, keep_entitlements: bool = True) -> None:
    cmd = [self.ldid, "-S"]
    if keep_entitlements:
      cmd.append("-M")

    subprocess.run(cmd + [self.path])

  def change_dependency(self, old: str, new: str) -> None:
    subprocess.run([self.nt, "-change", old, new, self.path])

  def insert_cmd(self, cmd: str) -> None:
    if self.inj is None:
      lief.logging.disable()
      self.inj = lief.parse(self.path)  # type: ignore

    self.inj.add(lief.MachO.DylibCommand.weak_lib(cmd))  # type: ignore

  def ios_inject(self, cmd: str) -> None:
    subprocess.run(
      [
        f"{self.specific}/insert_dylib",
        "--weak", "--inplace", "--no-strip-codesig", "--all-yes",
        cmd, self.path
      ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

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

