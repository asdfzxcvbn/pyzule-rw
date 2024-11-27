import sys
import plistlib
from glob import glob
from typing import Optional, Any

class Plist:
  def __init__(
      self, path: str, app_path: Optional[str] = None, throw: bool = True
  ):
    try:
      with open(path, "rb") as f:
        self.data: dict[str, Any] = plistlib.load(f)

      self.success = True
    except Exception:
      if throw:
        sys.exit(f"[!] couldn't read {path}")

      self.success = False

    self.path = path
    self.app_path = app_path

  def __getitem__(self, key: str) -> Any:
    return self.data.get(key, None)

  def __setitem__(self, key: str, val: Any) -> None:
    self.data[key] = val

  def __contains__(self, key: str) -> bool:
    return key in self.data

  def save(self) -> None:
    with open(self.path, "wb") as f:
      plistlib.dump(self.data, f)

  def remove(self, key: str) -> bool:
    try:
      del self.data[key]
      self.save()
      return True
    except KeyError:
      return False

  def change(self, val: Any, *keys: str) -> bool:
    try:
      if all(self[key] == val for key in keys):
        return False
      raise KeyError
    except KeyError:
      for key in keys:
        self[key] = val

    self.save()
    return True

  def remove_uisd(self) -> None:
    if self.remove("UISupportedDevices"):
      print("[*] removed UISupportedDevices")
    else:
      print("[?] no UISupportedDevices")

  def enable_documents(self) -> None:
    c1 = self.change(True, "UISupportsDocumentBrowser")
    c2 = self.change(True, "UIFileSharingEnabled")

    if c1 or c2:
      print("[*] enabled documents support")
    else:
      print("[?] documents support was already enabled")

  def change_name(self, name: str) -> None:
    if self.change(name, "CFBundleName", "CFBundleDisplayName"):
      print(f"[*] changed name to \"{name}\"")
      changed = 0

      for lproj in glob(f"{self.app_path}/*.lproj"):
        try:
          pl = Plist(f"{lproj}/InfoPlist.strings", None, False)
          pl.change(name, "CFBundleName", "CFBundleDisplayName")
          pl.save()
          changed += 1
        except Exception:
          pass  # file might not exist

      if changed != 0:
        print(f"[*] changed \033[96m{changed}\033[0m localized names")
    else:
      print(f"[?] name was already \"{name}\"")

  def change_version(self, version: str) -> None:
    if self.change(version, "CFBundleVersion", "CFBundleShortVersionString"):
      print(f"[*] changed version to \"{version}\"")
    else:
      print(f"[?] version was already \"{version}\"")

  def change_bundle_id(self, bundle_id: str) -> None:
    orig = self["CFBundleIdentifier"]

    if self.change(bundle_id, "CFBundleIdentifier"):
      print(f"[*] changed bundle id to \"{bundle_id}\"")
      changed = 0

      # change all other bundle ids
      for ext in glob(f"{self.app_path}/*/*.appex"):
        try:
          pl = Plist(f"{ext}/Info.plist", None, False)
          current = pl["CFBundleIdentifier"]
          pl["CFBundleIdentifier"] = current.replace(orig, bundle_id)
          pl.save()
          changed += 1
        except Exception:
          pass  # how tf would it not exist? idk

      if changed != 0:
        print(f"[*] changed \033[96m{changed}\033[0m other bundle ids")
    else:
      print(f"[?] bundle id was already \"{bundle_id}\"")

  def change_minimum_version(self, minimum: str) -> None:
    if self.change(minimum, "MinimumOSVersion"):
      print(f"[*] changed minimum version to \"{minimum}\"")
    else:
      print(f"[?] minimum version was already \"{minimum}\"")

  def merge_plist(self, path: str) -> None:
    pl = Plist(path, throw=False)
    if not pl.success:
      return print(f"[!] couldn't parse {path}")

    changed = False
    for k, v in pl.data.items():
      if self.change(v, k):
        changed = True

    if not changed:
      print("[?] no modified plist entries")
    else:
      print("[*] set plist keys:", ", ".join(pl.data))

