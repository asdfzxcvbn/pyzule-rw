from setuptools import setup

setup(
  name="cyan",
  version="1.0",
  description="finally, pyzule doesn't suck",
  author="zx",
  author_email="hi@zxcvbn.fyi",
  packages=["cyan", "cyan.tbhtypes"],
  # install_requires=["lief"],
  python_requires=">=3.10",
  include_package_data=True,
  entry_points={
    "console_scripts": ["cyan=cyan.__main__:main"],
  }
)

