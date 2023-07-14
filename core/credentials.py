#!/usr/bin/env python3


from Crypto.Hash import SHA
from Crypto.PublicKey import RSA


class CredentialError(Exception):
    def __init__(self, msg, original_exception=None):
        super().__init__(f"{msg} {original_exception}")
        self.original_exception = original_exception


class Credentials:
    """Identify a digital authority"""

    def __init__(self, pkey, cert, dfunction=None, ask=None, hardcoded_r2=None, hardcoded_dask=None):
        """Private key and public certificate are mandatory.

        To be able to generate DASk provide one of:
        - DFunction + ASk
        - hardcoded_r2 + hardcoded_dask
        """

        try:
            with open(pkey, "r") as f:
                self.pkey = RSA.importKey(f.read(), passphrase="capdream12")
        except FileNotFoundError as e:
            raise CredentialError("Unable to load pkey", e) from e

        try:
            with open(cert, "rb") as f:
                self.cert_hash = SHA.new(f.read()).digest()
        except FileNotFoundError as e:
            raise CredentialError("Unable to load cert", e) from e

        self.dfunction = None
        self.ask = None

        # Hardcoded values in case Dfunction is not available (Key Server Module package)
        self.hardcoded_r2 = None
        if hardcoded_r2:
            try:
                with open(hardcoded_r2, "rb") as f:
                    self.hardcoded_r2 = f.read()
            except FileNotFoundError as e:
                raise CredentialError("Unable to load hardcoded_r2", e) from e

        self.hardcoded_dask = None
        if hardcoded_r2:
            try:
                with open(hardcoded_r2, "rb") as f:
                    self.hardcoded_r2 = f.read()
            except FileNotFoundError as e:
                raise CredentialError("Unable to load hardcoded_r2", e) from e
        self.hardcoded_dask = None
        if hardcoded_dask:
            with open(hardcoded_dask, "rb") as f:
                self.hardcoded_dask = f.read()

    def get_dask(self, r2):
        # If ask and Dfunction are available, derive dask
        if self.ask and self.dfunction:
            # Call to Dfunction
            # Not implemented as part of the "Key Server Module" package
            return None
        elif self.hardcoded_r2 and self.hardcoded_dask:
            if r2 != self.hardcoded_r2:
                raise CredentialError("Mismatch between R2 and hadcoded R2")
            return self.hardcoded_dask
        else:
            raise CredentialError("Cannot get DASk")
