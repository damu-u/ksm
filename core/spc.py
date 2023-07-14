#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from core.credentials import CredentialError
from core.TLLVContainer import TLLVContainer
from utilities.utilities import format_hex
import binascii
import base64


class SPC(TLLVContainer):

    def __init__(self):
        self.version = int()
        self.reserved = bytes()
        self.data_iv = bytes()  # Terminology: SPC data = SPC encrypted payload
        self.encrypted_AES128_key = bytes()
        self.certificate_hash = bytes()
        self.payload_length = int()
        self.data = bytes()
        self.spck = bytes()
        self.dask = bytes()
        # Init self.payload, self.tllvs and self.tag_TLLVs
        super().__init__()

    def select_credential(self, credentials):
        for c in credentials:
            if c.cert_hash == self.certificate_hash:
                return c

    def parse(self, spc, credentials=[]):
        """ Parse the incoming SPC message

        credentials is the list of credentials supported by the server
        """

        # Open the spc
        with open(spc, "rb") as f:
            raw_spc = f.read()
            try:
                raw_spc = base64.b64decode(raw_spc, validate=True)
            except binascii.Error:
                pass

        # Parse the container
        self.parse_container(raw_spc)

        # Select the proper credential
        #
        # A server can be identified with several certificates.
        # The SPC needs to select the proper certificate babsed on the certificate_hash field.
        credential = self.select_credential(credentials)
        if not credential:
            print("No credential found")
            return  # Cannot parse more

        # Good practice
        self.verify_certificate_hash(credential.cert_hash)

        # Decrypt encrypted_AES128_key to obtain spck
        self.decrypt_encrypted_AES128_key(credential.pkey)

        # Decrypt the SPC payload
        self.decrypt_payload()

        # Parse the SPC payload
        self.parse_TLLVs()

        # Decrypt the [SK..R1] payload
        try:
            self.dask = credential.get_dask(self.tllvs["r2"].value)
        except CredentialError as e:
            print(e)
            return

        self.tllvs["sk_r1"].decrypt(self.dask)

        # Good practice
        self.check_integrity()

    def parse_container(self, raw_spc):
        # Parse the SPC container
        assert len(raw_spc) >= 176
        self.version = int.from_bytes(raw_spc[0:4], byteorder="big")
        self.reserved = raw_spc[4:8]
        self.data_iv = raw_spc[8:24]
        self.encrypted_AES128_key = raw_spc[24:152]
        self.certificate_hash = raw_spc[152:172]
        self.payload_length = int.from_bytes(raw_spc[172:176], byteorder="big")
        self.data = raw_spc[176:]

        # Assert SPC container
        assert self.version == 1
        assert self.reserved == bytes([0, 0, 0, 0])
        assert self.payload_length == len(self.data)

    def verify_certificate_hash(self, cert_hash):
        assert cert_hash == self.certificate_hash, f"Mismatch between the certificate_hash field of the SPC container"

    def decrypt_encrypted_AES128_key(self, pkey):
        self.spck = PKCS1_OAEP.new(pkey).decrypt(self.encrypted_AES128_key)

    def decrypt_payload(self):
        self.payload = AES.new(self.spck, AES.MODE_CBC, self.data_iv).decrypt(self.data)

    def check_integrity(self):
        assert self.tllvs["sk_r1"].integrity == self.tllvs[
            "sk_r1_integrity"].value, "[SK..R1] integrity bytes do not match the value in SKR1 Integrity tag"

    def __str__(self):
        s = ""
        s += "=" * 80 + "\n"
        s += "SPC container\n\n"
        try:
            s += f"version:   {self.version}" + "\n"
            s += "reserved:  " + format_hex(self.reserved, "")
            s += "data iv:   " + format_hex(self.data_iv, "")
            s += "encrypted AES128 key:\n" + format_hex(self.encrypted_AES128_key, " "*12)
            s += "certificate hash:\n" + format_hex(self.certificate_hash, indent=" "*12)
            s += f"payload length: {self.payload_length:#x}\n"
            s += "SPCK:  " + format_hex(self.spck)
            s += "DASk:  " + format_hex(self.dask)
            s += "-" * 80 + "\n"
            if self.tllvs:
                s += super().__str_tllvs__()
        except AttributeError:
            pass
        return s
