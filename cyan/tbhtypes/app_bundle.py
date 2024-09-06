import os
import shutil

from cyan.tbhutils import get_plist
from .executable import Executable


class AppBundle:
  def __init__(self, path: str, plist_path: str):
    self.path = path
    self.plist = get_plist(plist_path)

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

