#!/usr/bin/env python3

from Crypto.Hash import SHA
from Crypto.Cipher import AES
from core.TLLVContainer import TLLVContainer
from utilities.utilities import format_hex
import base64
import binascii


class CKC(TLLVContainer):

    def __init__(self):
        self.raw_ckc = None
        self.version = None
        self.reserved = None
        self.data_iv = None
        self.payload_length = None
        self.data = None  # Terminology: this field is also called payload length
        self.AR_value = None
        self.encrypted_AR_seed = None
        # Init self.payload, self.TLLVs and self.tag_tllvs
        super().__init__()

    def parse_container(self, ckc):

        with open(ckc, "rb") as f:
            raw_ckc = f.read()
            try:
                raw_ckc = base64.b64decode(raw_ckc, validate=True)
            except binascii.Error:
                pass

        assert len(raw_ckc) >= 28, "The CKC container must at least be 28 bytes"
        self.version = raw_ckc[0:4]
        self.reserved = raw_ckc[4:8]
        self.data_iv = raw_ckc[8:24]
        self.payload_length = raw_ckc[24:28]
        self.data = raw_ckc[28:]
        # Convert values
        self.version = int.from_bytes(self.version, byteorder="big")
        self.payload_length = int.from_bytes(self.payload_length, byteorder="big")
        # Assert CKC container
        assert self.version == 1
        assert self.reserved == bytes([0, 0, 0, 0])
        assert self.payload_length == len(
            self.data), f"Mismatch between the payload_length field of the CKC container: "
        "{self.payload_length} and the actual length of the CKC payload: {len(self.data)}"

    def generate_encrypted_AR_seed(self, spc):
        self.AR_key = SHA.new(spc.tllvs["sk_r1"].r1).digest()[0:16]
        self.encrypted_AR_seed = AES.new(self.AR_key, AES.MODE_ECB).encrypt(spc.tllvs["ar_seed"].value)

    def decrypt_payload(self, spc):
        self.generate_encrypted_AR_seed(spc)
        self.payload = AES.new(self.encrypted_AR_seed, AES.MODE_CBC, self.data_iv).decrypt(self.data)

    def parse(self, raw_ckc, spc=None):
        # Parse the container
        self.parse_container(raw_ckc)

        # Decrypt the CKC payload
        try:
            self.decrypt_payload(spc)
        except AttributeError:
            print("Cannot decrypt CKC payload")
            return

        # Parse the SPC payload
        self.parse_TLLVs()

        # Verify that the CKC includes the "return request tllvs"
        for tag in spc.tllvs["return_request"].tags:
            assert tag in self.tag_tllvs, f"Missing {tag} tag required by SPC return request"

    def __str__(self):
        s = ""
        s += "=" * 80 + "\n"
        s += "CKC container\n\n"
        s += f"version:   {self.version}" + "\n"
        s += "reserved:  " + format_hex(self.reserved, "")
        s += "data iv:   " + format_hex(self.data_iv, "")
        s += f"payload length: {self.payload_length:#x}\n"
        s += "-" * 80 + "\n"
        s += super().__str_tllvs__()
        return s
