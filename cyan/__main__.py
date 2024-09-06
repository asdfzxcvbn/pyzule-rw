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
    "-u", "--remove-supported-devices", action="store_true",
    help="remove UISupportedDevices"
  )
  parser.add_argument(
    "-w", "--no-watch", action="store_true",
    help="remove all watch apps"
  )
  parser.add_argument(
    "-d", "--enable-documents", action="store_true",
    help="enable documents support"
  )
  parser.add_argument(
    "-s", "--fakesign", action="store_true",
    help="fakesign all binaries for use with appsync/trollstore"
  )

  parser.add_argument(
    "-c", "--compress", metavar="level", type=int, default=6,
    help="the compression level of the ipa (0-9, defaults to 6)",
    action="store", choices=range(0, 10)
  )
  parser.add_argument(
    "--ignore-encrypted", action="store_true",
    help="skip main binary encryption check"
  )

  parser.add_argument(
    "-v", "--version", action="version", version="cyan v1.0b"
  )

  from cyan import logic
  logic.main(parser)


if __name__ == "__main__":
  main()

