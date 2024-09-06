import os
import shutil
from glob import glob
from typing import Optional

from .executable import Executable
from .plist import Plist

class AppBundle:
  def __init__(self, path: str, plist_path: str):
    self.path = path
    self.plist = Plist(plist_path)

    self.executable = Executable(
      f"{path}/{self.plist['CFBundleExecutable']}",
      path
    )

    self.cached_executables: Optional[list[str]] = None

  def remove(self, name: str) -> bool:
    path = f"{self.path}/{name}"
    if not os.path.exists(path):
      return False

    try:
      shutil.rmtree(path)
    except NotADirectoryError:
      os.remove(path)

    return True

  def remove_watch_apps(self) -> None:
    removed = False
    for name in ("Watch", "WatchKit", "com.apple.WatchPlaceholder"):
      if self.remove(name):
        removed = True

    if removed:
      print("[*] removed watch app")
    else:
      print("[?] watch app not present")

  def get_executables(self) -> list[str]:
    return sum((
        glob(f"{self.path}/**/*.dylib", recursive=True),
        glob(f"{self.path}/**/*.appex", recursive=True),
        glob(f"{self.path}/**/*.framework", recursive=True)
    ), [])  # type: ignore

  def mass_operate(self, op: str, func: str) -> None:
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

