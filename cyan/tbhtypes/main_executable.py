import os
import shutil
import subprocess

from cyan import tbhutils
from .executable import Executable

class MainExecutable(Executable):
  def __init__(self, path: str, bundle_path: str):
    super().__init__(path)
    self.bundle_path = bundle_path

  def inject(self, tweaks: dict[str, str], tmpdir: str) -> None:
    ENT_PATH = f"{self.bundle_path}/cyan.entitlements"
    PLUGINS_DIR = f"{self.bundle_path}/PlugIns"
    FRAMEWORKS_DIR = f"{self.bundle_path}/Frameworks"
    has_entitlements = self.write_entitlements(ENT_PATH)

    # iirc, injecting doesnt work (sometimes) if the file is signed
    self.remove_signature()

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

    # `extract_deb()` will modify `tweaks`, which is why we make a copy
    cwd = os.getcwd()
    for bn, path in dict(tweaks).items():
      if bn.endswith(".deb"):
        tbhutils.extract_deb(path, tweaks, tmpdir)
        continue
    os.chdir(cwd)  # i fucking hate jailbroken iOS utils.

    needed: set[str] = set()
    for bn, path in tweaks.items():
      if bn.endswith(".appex"):
        fpath = f"{PLUGINS_DIR}/{bn}"
        existed = tbhutils.delete_if_exists(fpath, bn)
        shutil.copytree(path, fpath)
      elif bn.endswith(".dylib"):
        path = shutil.copy2(path, tmpdir)
        Executable(path).fix_dependencies(tweaks, needed)

        fpath = f"{FRAMEWORKS_DIR}/{bn}"
        existed = tbhutils.delete_if_exists(fpath, bn)
        self.inj_func(f"@rpath/{bn}")
        shutil.move(path, FRAMEWORKS_DIR)
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

    # orion has a *weak* dependency to substrate,
    # but will still crash without it. nice !!!!!!!!!!!
    if "Orion.framework" in needed:
      needed.add("CydiaSubstrate.framework")

    for missing in needed:
      real = self.common[missing]  # "real" name, thanks substrate!
      ip = f"{FRAMEWORKS_DIR}/{real}"
      existed = tbhutils.delete_if_exists(ip, real)
      shutil.copytree(f"{self.install_dir}/extras/{real}", ip)

      if not existed:
        print(f"[*] auto-injected {real}")

    # FINALLY !!
    if self.inj is not None:  # type: ignore
      self.inj.write(self.path)  # type: ignore

    if has_entitlements:
      self.sign_with_entitlements(ENT_PATH)
      print("[*] restored entitlements")

  def write_entitlements(self, output: str) -> bool:
    with open(output, "wb") as entf:
      proc = subprocess.run(
        [self.ldid, "-e", self.path],
        capture_output=True
      )

      entf.write(proc.stdout)

    return os.path.getsize(output) > 0

  def merge_entitlements(self, entitlements: str) -> None:
    self.sign_with_entitlements(entitlements)
    print("[*] merged new entitlements")

  def sign_with_entitlements(self, entitlements: str) -> bool:
    return subprocess.run(
      [self.ldid, f"-S{entitlements}", "-M", self.path]
    ).returncode == 0

