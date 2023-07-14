#!/usr/bin/env python3

"""Server credential configuration"""

from core.credentials import Credentials


credentials = []

credentials.append(
        Credentials(
            pkey='../Credentials/privateKey.pem',
            cert='../Credentials/fairplay.cer',
            hardcoded_r2='../r2.bin',
            hardcoded_dask='../dask.bin',
            )
        )
