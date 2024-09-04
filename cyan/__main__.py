#!/usr/bin/env python3
# cyan, aka pyzule-rw; by zx, 2024

import sys
import argparse


def main() -> None:
  if sys.platform == "win32":
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
    "--ignore-encrypted", action="store_true",
    help="skip main binary encryption check"
  )

  from cyan import logic
  logic.main(parser)


if __name__ == "__main__":
  main()

