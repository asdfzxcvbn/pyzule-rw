# type: ignore

from setuptools import setup

setup(
  name="cyan",
  version="1.2",
  description="finally, pyzule doesn't suck",
  author="zx",
  author_email="zx@hrzn.email",
  packages=["cyan", "cyan.tbhtypes", "cgen"],
  python_requires=">=3.9",
  include_package_data=True,
  entry_points={
    "console_scripts": [
      "cyan=cyan.__main__:main",
      "cgen=cgen.__main__:main"
    ],
  }
)

