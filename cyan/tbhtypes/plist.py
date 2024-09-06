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

  def __setitem__(self, key: str, val: Any) -> None:
    self.data[key] = val

  def save(self) -> None:
    with open(self.path, "wb") as f:
      plistlib.dump(self.data, f)

  def remove(self, key: str) -> bool:
    try:
      del self.data[key]
      return True
    except KeyError:
      return False

  def change(self, key: str, val: Any) -> bool:
    try:
      if self[key] == val:
        return False
    except KeyError:
      self[key] = val

    return True

  def remove_uisd(self) -> None:
    if self.remove("UISupportedDevices"):
      self.save()
      print("[*] removed UISupportedDevices")
    else:
      print("[?] no UISupportedDevices")

  def enable_documents(self) -> None:
    c1 = self.change("UISupportsDocumentBrowser", True)
    c2 = self.change("UIFileSharingEnabled", True)

    if c1 or c2:
      self.save()
      print("[*] enabled documents support")
    else:
      print("[?] documents support was already enabled")

