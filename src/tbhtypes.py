import os
import sys
from subprocess import run

import tbhutils


class AppBundle:
  def __init__(self, path: str, plist_path: str):
    self.path = path
    self.plist = tbhutils.get_plist(plist_path)
    self.executable = Executable(
      f"{path}/{self.plist["CFBundleExecutable"]}"
    )


class Executable:
  td = tbhutils.get_tools_dir()
  otool = f"{td}/otool"

  def __init__(self, path: str):
    if not os.path.isfile(path):
      sys.exit(f"[!] {path} does not exist (executable)")

    self.path = path

  def is_encrypted(self) -> bool:
    proc = run([self.otool, "-l", self.path])
    return b"cryptid 1" in proc.stdout


