#!/usr/bin/env python3


from core.TLLVS_common import *
import core.TLLV as TLLV
import sys
import inspect


class TLLVContainer:
    """ Container of TLLVs """

    def __init__(self):
        self.payload = bytes()
        self.tllvs = {}  # TLLVs indexed by TLLV names.
        self.tag_tllvs = {}  # TLLVs indexed by TLLV tag value (i.e. 0x3d1a10b8bffac2ec)

    def parse_TLLVs(self):
        """ Deserialize the TLLVs """

        payload = self.payload

        while payload:
            assert len(payload) >= 16, "Cannot parse TLLV not enough bytes"

            # Parse the TLLV
            tag = int.from_bytes(payload[0:8], byteorder="big")
            block_length = int.from_bytes(payload[8:12], byteorder="big")
            value_length = int.from_bytes(payload[12:16], byteorder="big")

            # Get TLLV value and padding
            assert value_length <= block_length, "Cannot parse TLLV, value_length > block_length"
            assert 16 + block_length <= len(payload), "Cannot parse TLLV, not enough bytes in the value+padding"
            value = payload[16:16 + value_length]
            padding = payload[16 + value_length:16 + block_length]

            # Create the TLLV and index it
            tllv = TLLV.TLLV_MAP[tag](tag, block_length, value_length, value, padding)
            self.tag_tllvs[tag] = tllv  # Index by tag value
            if not isinstance(tllv, TLLV.Unknown):
                self.tllvs[tllv.FIELD] = tllv  # Index by field name

            # Move the payload "pointer"
            payload = payload[16+block_length:]

    def __str_tllvs__(self):
        s = ""
        for v in self.tag_tllvs.values():
            s += v.__str__() + "\n"
        return s

    def __str_known_tllvs__(self):
        s = ""
        for v in self.tllvs.values():
            s += v.__str__() + "\n"
        return s

# Create the TLLV_MAP
for cls in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if issubclass(cls[1], TLLV.TLLV) and cls[1] != TLLV.Unknown:
        TLLV.TLLV_MAP.update({cls[1].TAG: cls[1]})
