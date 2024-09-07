import os
import shutil
from glob import glob
from typing import Optional, Literal

from .executable import Executable
from .plist import Plist

class AppBundle:
  def __init__(self, path: str):
    self.path = path
    self.plist = Plist(f"{path}/Info.plist")

    self.executable = Executable(
      f"{path}/{self.plist['CFBundleExecutable']}",
      path
    )

    self.cached_executables: Optional[list[str]] = None

  def remove(self, *names: str) -> bool:
    existed = False

    for name in names:
      if self.path in name:  # i do this in `remove_encrypted_extensions()`
        path = name
      else:
        path = f"{self.path}/{name}"

      if not os.path.exists(path):
        continue

      try:
        shutil.rmtree(path)
      except NotADirectoryError:
        os.remove(path)

      existed = True

    return existed

  def remove_watch_apps(self) -> None:
    if self.remove("Watch", "WatchKit", "com.apple.WatchPlaceholder"):
      print("[*] removed watch app")
    else:
      print("[?] watch app not present")

  def get_executables(self) -> list[str]:
    return sum((
        glob(f"{self.path}/**/*.dylib", recursive=True),
        glob(f"{self.path}/**/*.appex", recursive=True),
        glob(f"{self.path}/**/*.framework", recursive=True)
    ), [])  # type: ignore

  def mass_operate(self, op: str, func: Literal["fakesign", "thin"]) -> None:
    # this works since we call this after injecting
    if self.cached_executables is None:
      self.cached_executables = self.get_executables()

    if getattr(self.executable, func)():
      count = 1
    else:
      count = 0

    for ts in self.cached_executables:
      if ts.endswith(".dylib"):
        call = getattr(Executable(ts), func)()
      else:
        pl = Plist(f"{ts}/Info.plist")
        call = getattr(Executable(f"{ts}/{pl['CFBundleExecutable']}"), func)()

      if call:
        count += 1

    print(f"[*] {op} \033[96m{count}\033[0m item(s)")

  def fakesign_all(self) -> None:
    self.mass_operate("fakesigned", "fakesign")

  def thin_all(self) -> None:
    self.mass_operate("thinned", "thin")

  def remove_all_extensions(self) -> None:
    if self.remove("Extensions", "PlugIns"):
      print("[*] removed app extensions")
    else:
      print("[?] no app extensions")

  def remove_encrypted_extensions(self) -> None:
    removed: list[str] = []

    # a singular * is used to not detect watch apps
    for plugin in glob(
        f"{self.path}/*/*.appex", recursive=True
    ):
      bundle = AppBundle(plugin)
      if bundle.executable.is_encrypted():
        self.remove(plugin)
        removed.append(os.path.basename(bundle.executable.path))

    if len(removed) == 0:
      print("[?] no encrypted plugins")
    else:
      print("[*] removed encrypted plugins:", ", ".join(removed))

