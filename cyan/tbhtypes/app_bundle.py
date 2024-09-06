import os
import shutil
from glob import glob

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

  def fakesign_all(self) -> None:
    self.executable.fakesign()
    count = 1

    for ts in sum((
        glob(f"{self.path}/**/*.appex", recursive=True),
        glob(f"{self.path}/**/*.framework", recursive=True)
    ), []):  # type: ignore
      pl = Plist(f"{ts}/Info.plist")
      Executable(f"{ts}/{pl['CFBundleExecutable']}").fakesign()
      count += 1

    for ts in glob(f"{self.path}/**/*.dylib", recursive=True):
      Executable(ts).fakesign()
      count += 1

    print(f"[*] fakesigned \033[96m{count}\033[0m items")
