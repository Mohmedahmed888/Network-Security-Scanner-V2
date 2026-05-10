"""
Compatibility launcher.

The actual application entrypoint lives in `netscan/__main__.py`,
so the code sits inside its package folder.
"""

from netscan.__main__ import main


if __name__ == "__main__":
    main()
