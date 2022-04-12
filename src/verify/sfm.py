"""
Copyright (C) 2021 FARO Technologies Inc.
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License
version 3 or (at your option) any later version as published by the Free Software Foundation
and appearing in the file LICENSE included in the packaging of this file.

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This file defines the implementation of the actual verification algorithms
as well as data structures for representing the verification results.
"""

import os
import logging

from PyQt5 import QtWidgets, QtCore

from enum import Enum, auto, unique
import hashlib
from Cryptodome.Hash import SHA1 as cryptoSHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_PSS

logger = logging.getLogger(__name__)

class Sfm:
    """Functions for verification of SFM raw scans
    Functions for
    - checking if a files is a signed SFM raw scan
    - checking if a folder contains such files
    - getting a list of all SFM raw scan files in a folder
    - verify a SFM raw scan
    """

    def is_file(path) -> bool:
        """Takes a string (path) and checks if it is signed SFM raw data file"""

        return os.path.isfile(path) and (path.endswith(".sfm.signed") or path.endswith(".fsv.signed"))

    def is_hash(path) -> bool:
        """Takes a string (path) and checks if it is a SFM hashing file"""

        return os.path.isfile(path) and (path.endswith(".sha.signed") or path.endswith(".sig.signed"))

    def is_folder(path) -> bool:
        """Takes a string (path) and checks if the folder contains signed SFM raw data files"""

        if not os.path.isdir(path):
            return False

        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            if Sfm.is_file(item_path):
                return True

        return False

    def files(path):
        """Takes a string (path) and returns a list of all signed SFM raw data files"""

        sfm_files = []
        if not os.path.isdir(path) and Sfm.is_file(path):
            sfm_files.append(path)

        else:
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if Sfm.is_file(item_path):
                    sfm_files.append(item_path)

        return sfm_files
    
    def verify(path, signer):
        """Takes a string (path) and the path to the public key file

        Checks existence for hash and signature files
        Compares stored and calculated hashes
        Verifies the signature of the hash file
        Returns a VerificationResult from verification_algorithms.py
        """

        # Import from verification_algorithms here to avoid circular dependencies
        # Must rename function hash_file from verification_algorithms, because this function uses a variable hash_file
        from .verification_algorithms import HashResult, SignatureResult, VerificationResult, HashedFileInfo
        from .verification_algorithms import hash_file as calculate_hash

        logger.info("Checking the validity of file '%s'", path)

        result = VerificationResult(path)
        result.hash_result = HashResult.PASSED
        result.sign_result = SignatureResult.PASSED

        if Sfm.is_hash(path):
            result.sub_hashes[path] = HashedFileInfo(path)
            return result

        # Check if necessary files are there
        if not Sfm.is_file(path):
            result.hash_result = HashResult.FAILED
            result.sign_result = SignatureResult.FAILED
            return result

        hash_file = path.replace(".sfm.signed", ".sha.signed").replace(".fsv.signed", ".sha.signed")
        if not os.path.isfile(hash_file):
            result.hash_result = HashResult.HASH_TOTAL_MISSING
            result.sign_result = SignatureResult.FAILED
            return result

        signature_file = path.replace(".sfm.signed", ".sig.signed").replace(".fsv.signed", ".sig.signed")
        if not os.path.isfile(signature_file):
            result.hash_result = HashResult.FAILED
            result.sign_result = SignatureResult.NO_SIGN_FILE
            return result

        # Check hash
        result.total_hash_calc = calculate_hash(path)

        try:
            result.total_hash_read = open(hash_file, "r").read()
        except Exception as ex:
            logger.error("Exception: {}".format(ex))
            result.hash_result = HashResult.FAILED
            result.sign_result = SignatureResult.HASH_FILE_FAILED
            return result

        if result.total_hash_calc.casefold() != result.total_hash_read.casefold():
            result.hash_result = HashResult.FAILED
            result.sign_result = SignatureResult.FAILED
            return result

        # Check signature
        # Note: Must read hash file in raw mode
        try:
            # Load signature and signed hash file
            signature = open(signature_file, "rb").read()
            sha = open(hash_file, "rb").read()

            # Create digest
            digest = cryptoSHA.new()
            digest.update(sha)

            # Verify signature
            if not signer.verify(digest, signature):
                result.hash_result = HashResult.FAILED
                result.sign_result = SignatureResult.HASH_FILE_FAILED
                return result

        except Exception as ex:
            logger.error("Exception: {}".format(ex))
            result.hash_result = HashResult.FAILED
            result.sign_result = SignatureResult.INVALID_KEY
            return result

        return result
    