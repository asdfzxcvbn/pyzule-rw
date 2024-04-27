#!/usr/bin/python3
# cyan, aka pyzule-rw; by zx, 2024

import os
import sys
import argparse

parser = argparse.ArgumentParser(
    description="cyan, an azule \"clone\" for modifying iOS apps")
parser.add_argument("-o", metavar="output",
                    help="if unspecified, overwrites input")
parser.add_argument("-f", metavar="file", nargs="+",
                    help="a tweak to inject/item to be added to the bundle")

parser.add_argument("--overwrite", action="store_true",
                    help="skip overwrite confirmation")

parser.add_argument("input", help="the app to be modified (.app/.ipa)")
args = parser.parse_args()

INPUT = os.path.realpath(args.input)
WORKING_DIR = os.getcwd()
PZ_DIR = os.path.expanduser("~/.config/cyan")
changed = False

if not (INPUT.endswith(".ipa") or INPUT.endswith(".app")):
    sys.exit("[!] input must be a .ipa/.app")
elif not os.path.exists(INPUT):
    sys.exit("[!] input does not exist")
elif not args.o and (input("[<] override your input file? [y/N] ").strip()
                     .lower() not in ("y", "yes")):
    sys.exit("[!] not overriding input, missing -o")
