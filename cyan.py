# cyan, aka pyzule-rw; by zx, 2024

import os
import sys
import argparse

parser: argparse.ArgumentParser = argparse.ArgumentParser(
    description="cyan, an azule \"clone\" for modifying iOS apps")
parser.add_argument("-o", metavar="output",
                    help="if unspecified, overwrites input")
parser.add_argument("-f", metavar="file", nargs="+",
                    help="a tweak to inject/item to be added to the bundle")
parser.add_argument("input", help="the app to be modified (.app/.ipa)")
args: argparse.Namespace = parser.parse_args()

INPUT: str = os.path.realpath(args.input)
WORKING_DIR: str = os.getcwd()
PZ_DIR: str = os.path.expanduser("~/.config/cyan")
changed: bool = False

if not (INPUT.endswith(".ipa") or INPUT.endswith(".app")):
    sys.exit("[!] input must be a .ipa/.app")
elif not os.path.exists(INPUT):
    sys.exit("[!] input does not exist")
elif not args.o and (input("[<] override your input file? [y/N] ").strip()
                    .lower() not in ("y", "yes")):
    sys.exit("[!] not overriding input, missing -o")
