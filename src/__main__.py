#!/usr/bin/env python3
# cyan, aka pyzule-rw; by zx, 2024

import sys
import argparse

import cyan


def main() -> None:
  if sys.version_info < (3, 12):
    sys.exit("[!] please upgrade to python 3.12 or higher")
  elif sys.platform == "win32":
    sys.exit("[!] windows is not supported")

  parser = argparse.ArgumentParser(
    description="cyan, an azule \"clone\" for modifying iOS apps"
  )

  parser.add_argument(
    "-i", "--input", metavar="input", required=True,
    help="the app to be modified (.app/.ipa)"
  )
  parser.add_argument(
    "-o", "--output", metavar="output",
    help="if unspecified, overwrites input"
  )

  parser.add_argument(
    "-f", metavar="file", nargs="+",
    help="a tweak to inject/item to be added to the bundle"
  )

  parser.add_argument(
    "--overwrite", action="store_true",
    help="skip overwrite confirmation"
  )
  parser.add_argument(
    "--ignore-encrypted", action="store_true",
    help="skip main binary encryption check"
  )

  cyan.main(parser)


if __name__ == "__main__":
  main()

