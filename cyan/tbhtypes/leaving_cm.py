class LeavingCM:
  def __enter__(self):
    pass

  def __exit__(self, i, d, c):  # type: ignore
    print("[*] deleting temporary directory..")

