#!/usr/bin/env python3


from collections import defaultdict
from utilities.utilities import format_hex

class TLLV:
    """ Base TLLV class

    Straight-forward TLLV implementation without any layer of interpretation.
    All the TLLVS should inherit from this class. """

    NAME = "TLLV Base class"

    def __init__(self, tag, block_length=0, value_length=0, value=bytes(), padding=bytes()):
        self.tag = tag
        self.block_length = block_length
        self.value_length = value_length
        self.value = value
        self.padding = padding

        # Sanity checks
        assert self.value_length <= self.block_length
        assert self.value_length == len(self.value)
        assert self.block_length == self.value_length + len(self.padding)
        assert self.block_length % 16 == 0
        if not isinstance(self, Unknown):
            assert self.tag == self.TAG  # Verify binding with subclass

        # Parse/validate the value field of each TLLV
        try:
            self.parse()
        except AttributeError:  # TLLV-subclass does not implement parse
            pass

    def __str__(self):
        s = f"{self.NAME} -- {self.tag:#x}\n"
        s += f"\tBlock length: {self.block_length:#x}\n"
        s += f"\tValue length: {self.value_length:#x}\n"
        s += format_hex(self.value, "\t\t")
        return s


class Unknown(TLLV):
    NAME = "Unknown"
    # No field for this TLLV. We cannot reference tllvs['unknown'] since
    # several TLLVS might be unknowns.


TLLV_MAP = defaultdict(lambda: Unknown)
