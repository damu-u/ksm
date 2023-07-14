#!/usr/bin/env python3


from cfg.credentials import credentials
from core.ckc import CKC
from core.spc import SPC
import argparse


# Main

if __name__ == "__main__":

    parser = argparse.ArgumentParser(epilog=""" Display as much info as possible from the SPC and CKC.
    SPC header is always display.
    If a proper pkey/cert is given, use it to decrypt the SPC payload and display it.
    If a proper CKC is provided display its header.
    If a proper CKC is provided and matches the SPC, display its payload.
    """)
    parser.add_argument("--spc", type=str, metavar="spc file", help="binary or base64", required=True)
    parser.add_argument("--ckc", type=str, metavar="ckc file", help="binary or base64", required=False)
    args = parser.parse_args()

    # Create and parse the SPC element
    spc = SPC()
    spc.parse(args.spc, credentials)
    print(spc)

    if args.ckc:
        # Create and parse the CKC element
        ckc = CKC()
        ckc.parse(args.ckc, spc)
        print(ckc)
