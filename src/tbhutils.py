import os
from typing import Optional
from argparse import Namespace


def validate_inputs(args: Namespace) -> Optional[str]:
  if not (
      args.i.endswith(".ipa")
      or args.i.endswith(".app")
  ):
    return "the input file must be an ipa/app"

  if not os.path.exists(args.i):
    return f"{args.i} does not exist"



