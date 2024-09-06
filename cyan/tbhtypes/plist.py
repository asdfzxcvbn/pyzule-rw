import sys
import plistlib
from typing import Any

class Plist:
  def __init__(self, path: str):
    try:
      with open(path, "rb") as f:
        self.data: dict[str, Any] = plistlib.load(f)
    except Exception:
      sys.exit(f"[!] couldn't read {path}")

    self.path = path

  def __getitem__(self, key: str) -> Any:
    return self.data.get(key, None)

  def remove(self, key: str) -> bool:
    try:
      del self.data[key]
      return True
    except KeyError:
      return False

  def remove_uisd(self) -> None:
    if self.remove("UISupportedDevices"):
      print("[*] removed UISupportedDevices")
    else:
      print("[?] no UISupportedDevices")

