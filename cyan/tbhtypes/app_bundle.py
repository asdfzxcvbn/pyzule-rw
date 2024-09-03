from cyan.tbhutils import get_plist
from .executable import Executable


class AppBundle:
  def __init__(self, path: str, plist_path: str):
    self.path = path
    self.plist = get_plist(plist_path)

    self.executable = Executable(
      f"{path}/{self.plist["CFBundleExecutable"]}",
      path
    )

