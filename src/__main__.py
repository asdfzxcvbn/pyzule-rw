#!/usr/bin/env python3
# cyan, aka pyzule-rw; by zx, 2024

import argparse

import cyan


def main() -> None:
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

  cyan.main(parser)

if __name__ == "__main__":
  main()

# INPUT = os.path.realpath(args.input)
# WORKING_DIR = os.getcwd()
# PZ_DIR = os.path.expanduser("~/.config/cyan")
# changed = False

# if not (INPUT.endswith(".ipa") or INPUT.endswith(".app")):
#     sys.exit("[!] input must be a .ipa/.app")
# elif not os.path.exists(INPUT):
#     sys.exit("[!] input does not exist")
# elif not args.o and (input("[<] override your input file? [y/N] ").strip()
#                      .lower() not in ("y", "yes")):
#     sys.exit("[!] not overriding input, missing -o")
