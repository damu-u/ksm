#!/usr/bin/env python3

""" Utilities, no need to look here """


from itertools import zip_longest


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper("ABCDEFG", 3, "x") --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def format_hex(payload, indent="", line_size=16):
    """ Sugar syntax to display nicely a hex payload

    There should be a better way. """

    if isinstance(payload, int):
        payload = bytes.fromhex(f"{payload:x}")

    # Get the hex str representation of each byte
    hexstr = [f"{x:02x}" for x in payload]
    if not hexstr:  # Deal with empty payloads
        hexstr.append('--')

    # Over-complicated formatting. But the user should not care.
    s = ""
    for line in grouper(hexstr, line_size, fillvalue="--"):
        s += (indent + "  ".join(" ".join("{:2s}" for _ in range(4)) for _ in range(line_size // 4)) +
              "\n").format(*line)
    return s
