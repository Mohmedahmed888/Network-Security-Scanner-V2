"""
Copy this file to `local_settings.py` in the same folder.

`local_settings.py` is listed in `.gitignore` — it stays on your PC and is
not pushed to GitHub.
"""

# IPs you consider trusted (e.g. gateway). Used by `is_rogue_device()`.
TRUSTED_IPS = [  # type: list[str]
    # "192.168.1.1",
]
