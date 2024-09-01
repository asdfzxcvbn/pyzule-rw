import os
from argparse import ArgumentParser

import tbhutils


def main(parser: ArgumentParser) -> None:
  args = parser.parse_args()
  args.i = os.path.normpath(args.input)

  if args.output is not None:
    args.o = os.path.normpath(args.output)
    if not (args.o.endswith(".app") or args.o.endswith(".ipa")):
      print("[?] output's file extension not specified; will create ipa")
      args.o += ".ipa"
  else:
    args.o = args.i

  arg_err = tbhutils.validate_inputs(args)
  if arg_err is not None:
    parser.error(arg_err)

  # verbose notices
  if args.o

