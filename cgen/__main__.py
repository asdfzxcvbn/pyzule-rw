import os
import sys
import json
import zipfile
import argparse


def main() -> None:
  if sys.platform == "win32":
    sys.exit("[!] windows is not supported")

  parser = argparse.ArgumentParser(
    description="a tool to generate .cyan files"
  )

  parser.add_argument(
    "-o", "--output", metavar="output", required=True,
    help="output of the .cyan file"
  )

  parser.add_argument(
    "-f", metavar="file", nargs="+",
    help="a tweak to inject/item to be added to the bundle"
  )
  parser.add_argument(
    "-n", metavar="name",
    help="modify the app's name"
  )
  parser.add_argument(
    "-v", metavar="version",
    help="modify the app's version"
  )
  parser.add_argument(
    "-b", metavar="bundle id",
    help="modify the app's bundle id"
  )
  parser.add_argument(
    "-m", metavar="minimum",
    help="modify the app's minimum OS version"
  )
  parser.add_argument(
    "-k", metavar="icon",
    help="modify the app's icon"
  )
  parser.add_argument(
    "-l", metavar="plist",
    help="a plist to merge with the app's Info.plist"
  )
  parser.add_argument(
    "-x", metavar="entitlements",
    help="add or modify entitlements to the main binary"
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
    "-q", "--thin", action="store_true",
    help="thin all binaries to arm64, may largely reduce size"
  )
  parser.add_argument(
    "-e", "--remove-extensions", action="store_true",
    help="remove all app extensions"
  )
  parser.add_argument(
    "-g", "--remove-encrypted", action="store_true",
    help="only remove encrypted app extensions"
  )

  generate_cyan(parser)


def generate_cyan(parser: argparse.ArgumentParser) -> None:
  args = parser.parse_args()

  # input validation
  if args.m is not None and any(c not in "0123456789." for c in args.m):
    parser.error(f"invalid minimum OS version: {args.m}")
  if args.k is not None and not os.path.isfile(args.k):
    parser.error(f"{args.k} does not exist")
  if args.l is not None and not os.path.isfile(args.l):
    parser.error(f"{args.l} does not exist")
  if args.x is not None and not os.path.isfile(args.x):
    parser.error(f"{args.x} does not exist")
  if args.f is not None:
    fake = [f for f in args.f if not os.path.exists(f)]

    # it would be great if everyone was using python 3.12 !!!
    if len(fake) != 0:
      parser.error(f"the following file(s) do not exist: {', '.join(fake)}")

  if not args.output.endswith(".cyan"):
    print("[*] appended cyan file extension to output")
    args.output += ".cyan"
  if os.path.isfile(args.output):
    try:
      overwrite = input(
        f"[<] {args.output} already exists. overwrite? [Y/n] "
      ).lower().strip()
    except KeyboardInterrupt:
      sys.exit("\n[?] guess not")

    if overwrite not in ("y", "yes", ""):
      sys.exit("[>] quitting.")

  real_args = {k: v for k, v in dict(vars(args)).items() if v}
  del real_args["output"]

  for key in "fkxl":  # these need files
    if key in real_args:
      real_args[key] = True

  print("[*] generating..")
  with zipfile.ZipFile(
      args.output, "w", zipfile.ZIP_DEFLATED, compresslevel=1
  ) as zf:
    with zf.open("config.json", "w") as f:
      f.write(json.dumps(real_args).encode())

    if args.f is not None:
      for f in args.f:
        if os.path.isfile(f):
          zf.write(f, f"inject/{os.path.basename(f)}")
        else:  # G YHUJMNFTGYHNFTGYHTGYHUT6Y7UJM8RFTYHNR564TY
          if f.endswith("/"):
            f = f[:-1]  # yes this is needed to prevent a bug wtf
          for dp, _, files in os.walk(f):
            for f2 in files:
              thing = f"{dp}/{f2}"
              zf.write(
                thing,
                f"inject/{os.path.relpath(thing, os.path.dirname(f))}"
              )  # no, i don't know what this is doing.

    if args.k is not None:
      zf.write(args.k, "icon.idk")

    if args.l:
      zf.write(args.l, "merge.plist")

    if args.x:
      zf.write(args.x, "new.entitlements")


if __name__ == "__main__":
  main()

