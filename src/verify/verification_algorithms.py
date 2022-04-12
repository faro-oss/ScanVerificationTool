"""
Copyright (C) 2018 FARO Technologies Inc. 
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License 
version 3 or (at your option) any later version as published by the Free Software Foundation 
and appearing in the file LICENSE included in the packaging of this file.  

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This file defines the implementation of the actual verification algorithms
as well as data structures for representing the verification results.
"""

import hashlib
import logging
import os
import string
import textwrap
import typing

import olefile
from enum import Enum, auto, unique
from Cryptodome.Hash import SHA1 as cryptoSHA
from Cryptodome.Hash import SHA256 as cryptoSHAv2
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_PSS
from PyQt5 import QtCore

from .functions import does_spl_exist
from .sfm import *

"""
for signature verification
openssl dgst -sha1 -sigopt rsa_padding_mode:pss -verify /path/to/ScanSign_public_key.pem -signature SHA256SUM.sig SHA256SUM
"""

logger = logging.getLogger(__name__)

BLOCK_SIZE = 64 * 1024
SUM_LEVEL1 = "SHA256SUM"
SUM_LEVEL2 = "SHA256SUM.sha"
SIGNATURE = "SHA256SUM.sig"
CLASSID = b"\x90\xEF\x56\x6A\x20\x2D\xD5\x11\xAE\x96\x00\x50\xFC\x0D\xBD\xBD"
MAIN_PARAM_STREAM = "Main"
SCANS_SUBFOLDER = "Scans"
LSDATAV2_SCANDATA_SUBFOLDER = "ScanData"
LSDATAV2_VERSION_FILE = "Version"

SWIFT_SEQ_ID = "SwiftSequenceId"
SWIFT_HASH_LIST = "SwiftPrevHashes"


@unique
class HashResult(Enum):
    """ Enumeration for different results of the hash verification
    """
    PASSED = auto()
    NOT_CHECKED = auto()
    FAILED = auto()
    HASH_LIST_MISSING = auto()
    HASH_TOTAL_MISSING = auto()     # can be assumed: list of hashed files is present
    HASHED_FILE_MISSING = auto()    # can be assumed: list of hashed files is present
    FILE_HASH_FAILED = auto()       # can be assumed: all hashed files are present
    TOTAL_HASH_FAILED = auto()      # can be assumed: hashes of all hashed files match
    SWIFT_SEQ_UNCONFIRMED = auto()  # can be assumed: verification of this scan was otherwise successful
    # For all following can also be assumed: last scan of a Swift sequence has been verified successfully
    SWIFT_SEQ_SCAN_MISSING = auto()    # can be assumed: list of scans in sequence is present
    SWIFT_SCAN_BAD_SEQ = auto()        # can be assumed: list of scans in sequence is present
    SWIFT_SEQ_HASH_MISMATCH = auto()   # can be assumed: list of scans in sequence is present


@unique
class SignatureResult(Enum):
    """ Enumeration for different results of the hash verification
    """
    PASSED = auto()
    NOT_CHECKED = auto()
    FAILED = auto()
    NO_KEY_PROVIDED = auto()
    INVALID_KEY = auto()
    NO_SIGN_FILE = auto()
    NO_HASH_FILE = auto()
    HASH_FILE_FAILED = auto()
    HASH_CALC_FAILED = auto()


class VerificationResult:
    """ Stores the information about the finished scan verification
    """

    def __init__(self, scan_path: str, is_scanplan_project=False):
        self.scan_path = scan_path
        self.hash_result = HashResult.FAILED
        self.total_hash_read = ""
        self.total_hash_calc = ""
        self.sub_hashes = {}  # dict mapping the file name to details
        self.sign_result = SignatureResult.FAILED
        self.is_swift_scan = False
        self.is_swift_last_scan = False
        self.is_scanplan_project = is_scanplan_project
        # ScanPlan properties
        self.expected_hash = ""

    @property
    def expected_hash_result(self):
        if not self.is_scanplan_project:
            return HashResult.NOT_CHECKED

        if not self.expected_hash:
            return HashResult.NOT_CHECKED

        # Set expected hash passed when at least the first 5 characters are given
        if len(self.expected_hash) > 4 and str(self.total_hash_calc).startswith(self.expected_hash):
            return HashResult.PASSED
        else:
            return HashResult.FAILED

    def get_str(self, include_file_details=False):

        proj_type = "ScanPlan Project" if self.is_scanplan_project else "Scan path"

        if self.hash_result == HashResult.HASH_LIST_MISSING:
            all_template = "{proj_type} path: {path}\n\nHash result:\n{hash_details}"
            return all_template.format(proj_type=proj_type,
                                       path=self.scan_path,
                                       hash_details="Not a scan or hash list file is missing")

        all_template = ("$proj_type: $path" +
                        "\n\nHash result:\n$hash_details" +
                        ("\n\nMissing hashed files:\n$missing_files"
                         if self.hash_result == HashResult.HASHED_FILE_MISSING else "") +
                        "\n\nSignature result:\n$signature_details")

        if include_file_details:
            all_template += "\n\nFile details:\n$file_details"

        tpl = string.Template(all_template)

        hash_status_strings = [['Summary', "FAILED"],
                               ['All hashed files present', 'UNKNOWN'],
                               ['File-based hash OK for all files', 'UNKNOWN'],
                               ['Scan-wide hash file present', 'UNKNOWN'],
                               ['Scan-wide hash OK', 'UNKNOWN']]

        if self.is_swift_scan:
            assert not self.is_scanplan_project
            hash_status_strings.append(['Relation to a Focus Swift sequence', 'UNKNOWN'])
        if self.is_swift_last_scan:
            assert self.is_swift_scan
            hash_status_strings.append(['Focus Swift sequence complete', 'UNKNOWN'])
            hash_status_strings.append(['Focus Swift sequence correct', 'UNKNOWN'])

        if self.is_scanplan_project:
            assert not self.is_swift_scan and not self.is_swift_last_scan
            hash_status_strings.append(['Expected hash OK', 'UNKNOWN'])
            hash_status_strings.append(['Expected hash   ', self.expected_hash])

        hash_status_strings.append(['Calculated hash ', self.total_hash_calc])
        hash_status_strings.append(['Saved hash      ', self.total_hash_read])

        if self.hash_result == HashResult.PASSED:
            hash_status_strings[0][1] = 'PASSED'
            hash_status_strings[1][1] = 'YES'
            hash_status_strings[2][1] = 'YES'
            hash_status_strings[3][1] = 'YES'
            hash_status_strings[4][1] = 'YES'
            if self.is_swift_scan:
                hash_status_strings[5][1] = 'CONFIRMED'
            if self.is_swift_last_scan:
                hash_status_strings[6][1] = 'YES'
                hash_status_strings[7][1] = 'YES'
        elif self.hash_result == HashResult.HASHED_FILE_MISSING:
            hash_status_strings[1][1] = 'NO'
        elif self.hash_result == HashResult.FILE_HASH_FAILED:
            hash_status_strings[1][1] = 'YES'
            hash_status_strings[2][1] = 'NO'
        elif self.hash_result == HashResult.HASH_TOTAL_MISSING:
            hash_status_strings[1][1] = 'YES'
            hash_status_strings[2][1] = 'YES'
            hash_status_strings[3][1] = 'NO'
        elif self.hash_result == HashResult.TOTAL_HASH_FAILED:
            hash_status_strings[1][1] = 'YES'
            hash_status_strings[2][1] = 'YES'
            hash_status_strings[3][1] = 'YES'
            hash_status_strings[4][1] = 'NO'
        elif self.hash_result == HashResult.SWIFT_SEQ_UNCONFIRMED: # `is_swift_scan` can be assumed
            hash_status_strings[1][1] = 'YES'
            hash_status_strings[2][1] = 'YES'
            hash_status_strings[3][1] = 'YES'
            hash_status_strings[4][1] = 'YES'
            hash_status_strings[5][1] = 'NOT CONFIRMED'
        elif self.hash_result == HashResult.SWIFT_SCAN_BAD_SEQ:  # `is_swift_scan` can be assumed
            hash_status_strings[1][1] = 'YES'
            hash_status_strings[2][1] = 'YES'
            hash_status_strings[3][1] = 'YES'
            hash_status_strings[4][1] = 'YES'
            hash_status_strings[5][1] = 'DISPROVED'
        elif self.hash_result == HashResult.SWIFT_SEQ_SCAN_MISSING:  # `is_swift_last_scan` can be assumed
            hash_status_strings[1][1] = 'YES'
            hash_status_strings[2][1] = 'YES'
            hash_status_strings[3][1] = 'YES'
            hash_status_strings[4][1] = 'YES'
            hash_status_strings[5][1] = 'CONFIRMED'  # last scan belongs to its sequence by definition
            hash_status_strings[6][1] = 'NO'
        elif self.hash_result == HashResult.SWIFT_SEQ_HASH_MISMATCH:  # `is_swift_last_scan` can be assumed
            hash_status_strings[1][1] = 'YES'
            hash_status_strings[2][1] = 'YES'
            hash_status_strings[3][1] = 'YES'
            hash_status_strings[4][1] = 'YES'
            hash_status_strings[5][1] = 'CONFIRMED'  # last scan belongs to its sequence by definition
            hash_status_strings[6][1] = 'YES'  # only mark hash mismatch if all scans of a sequence are present
            hash_status_strings[7][1] = 'NO'
        else:
            logger.warning("Unknown hash result value: {0}".format(self.hash_result))

        if self.is_scanplan_project:
            if self.expected_hash_result == HashResult.PASSED:
                exp_str = 'YES'
            elif self.expected_hash_result == HashResult.NOT_CHECKED:
                exp_str = 'NOT CHECKED'
            else:
                exp_str = 'NO'
                hash_status_strings[0][1] = 'FAILED'

            hash_status_strings[5][1] = exp_str

        sign_status_strings = [['Summary', "FAILED"],
                               ['Key file present', 'UNKNOWN'],
                               ['Key file valid', 'UNKNOWN'],
                               ['Signature file present', 'UNKNOWN'],
                               ['Scan signature OK', 'UNKNOWN']]

        yes_until = 1
        if self.sign_result == SignatureResult.PASSED:
            yes_until += 4
            sign_status_strings[0][1] = "PASSED"
        elif self.sign_result == SignatureResult.NO_KEY_PROVIDED:
            sign_status_strings[1][1] = "NO"
        elif self.sign_result == SignatureResult.INVALID_KEY:
            yes_until += 1
            sign_status_strings[2][1] = "NO"
        elif self.sign_result == SignatureResult.NO_SIGN_FILE:
            yes_until += 2
            sign_status_strings[3][1] = "NO"
        elif self.sign_result == SignatureResult.NO_HASH_FILE:
            logger.warning("This should not occur: No hash list file when verifying the signature.")
        elif self.sign_result == SignatureResult.HASH_FILE_FAILED:
            yes_until += 3
            sign_status_strings[4][1] = "NO"
        else:
            logger.warning("Unknown signature verification result: {0}".format(self.sign_result))

        for i in range(1, yes_until):
            sign_status_strings[i][1] = "YES"

        file_details = []
        if include_file_details:
            single_file_template = "{name}: \n** File present: {present}\n** Hash matches: {status}\n" \
                                   "** Calculated hash: {hash_calc}\n** Saved hash:      {hash_saved}"
            # sub_hashes
            file_details = []
            for key in self.sub_hashes.keys():
                file_results = self.sub_hashes[key]
                assert isinstance(file_results, HashedFileInfo)
                file_details.append(single_file_template.format(name=key,
                                                                present="YES" if file_results.file_present else "NO",
                                                                status="YES" if file_results.hash_ok else "NO",
                                                                hash_calc=file_results.hash_calc,
                                                                hash_saved=file_results.hash_read))

        missing_files = []
        if self.hash_result == HashResult.HASHED_FILE_MISSING:
            for key in self.sub_hashes.keys():
                file_results = self.sub_hashes[key]
                assert isinstance(file_results, HashedFileInfo)
                if not file_results.file_present:
                    missing_files.append(file_results.relative_path)

        retval = tpl.safe_substitute(
            {'proj_type': proj_type,
             'path': self.scan_path,
             'hash_details': "\n".join(["* {0}: {1}".format(item[0], item[1])
                                        for item in hash_status_strings]),
             'signature_details': "\n".join(["* {0}: {1}".format(item[0], item[1])
                                             for item in sign_status_strings]),
             'missing_files': "\n".join(["* {0}".format(item) for item in missing_files]),
             'file_details': "\n".join(file_details)
             })
        return retval

    def __str__(self):
        return self.get_str(False)


class HashedFileInfo:

    def __init__(self, scan_path='', relative_path='', is_dir=False, file_present=False,
                 hash_ok=False, hash_calc='', hash_read='', note=''):
        """

        :rtype: object
        """
        self.scan_path = scan_path
        self.relative_path = relative_path
        self.is_dir = is_dir
        self.file_present = file_present
        self.hash_ok = hash_ok
        self.hash_calc = hash_calc
        self.hash_read = hash_read
        self.note = note


def hash_file_contents(file_like):
    hasher = hashlib.sha256()
    while True:
        data = file_like.read(BLOCK_SIZE)
        if not data:
            break
        hasher.update(data)
    return hasher.hexdigest()


def hash_file(in_file):
    if isinstance(in_file, str):
        with open(in_file, 'rb') as opened_file:
            return hash_file_contents(opened_file)

    else:
        return hash_file_contents(in_file)


def extract_swift_seq_id(in_file: typing.Union[str, typing.BinaryIO]) -> str:
    def internal(f: typing.BinaryIO) -> dict:
        # we expect the file to contain one single line
        return f.readline().decode('ASCII').rstrip('\n')

    if isinstance(in_file, str):
        with open(in_file, 'rb') as opened_file:
            return internal(opened_file)
    else:
        return internal(in_file)


def read_swift_hash_list(in_file: typing.Union[str, typing.BinaryIO]) -> dict:
    def internal(f: typing.BinaryIO) -> dict:
        r = {}
        for line in f.readlines():
            line_content = line.decode('ASCII').rstrip('\n').split(" *../")
            # the structure is "<hash> *../<scan_name>"
            if len(line_content) < 2:
                break
            r[line_content[1]] = line_content[0]
        return r

    if isinstance(in_file, str):
        with open(in_file, 'rb') as opened_file:
            return internal(opened_file)
    else:
        return internal(in_file)


def get_path_to_other(item_path, is_dir: bool, other_name: str):
    containing_folder = os.path.dirname(os.path.abspath(item_path))
    return os.path.abspath(os.path.join(containing_folder, other_name))


def hash_data(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()



def is_scan_verifyable(path: str) -> bool:
    return is_hashed_scan(path) or scan_count(path, check_any=True)

def ole_contains_stream(ole_path: str, stream: str) -> bool:
    """ For a given path, if it represents an OLE file,
        checks presence of a stream `stream` inside it.
    """
    try:
        if olefile.isOleFile(ole_path):
            with olefile.OleFileIO(ole_path) as ole:
                return ole.exists(stream)
    except EnvironmentError as error:
        logger.warning("Error when opening OLE file {1}: {0}".format(str(error), ole_path))
    return False

def is_swift_scan(path: str) -> typing.Optional[str]:
    """ For a given path, checks whether the path represents a scan
        belonging to a Swift sequence.
        Returns the Swift sequence ID if the scan belongs to a sequence,
        otherwise `None`.
    """
    if os.path.isdir(path):
        seq_file =  os.path.normpath(os.path.join(path, SWIFT_SEQ_ID))
        if os.path.exists(seq_file):
            return extract_swift_seq_id(seq_file)
    else:
        if ole_contains_stream(path, SWIFT_SEQ_ID):
            with olefile.OleFileIO(path) as ole:
                return extract_swift_seq_id(ole.openstream(SWIFT_SEQ_ID))
    return None

def is_last_scan_in_swift_seq(path: str, seq_id: str = "") -> bool:
    """ Checks whether the scan specified by a given path is the last scan
        of a Swift sequence. If @p seq_id is not an empty string,
        the relation of the given scan being the final scan of the specified
        sequence is additionally checked.
    """
    maybe_seq_id = is_swift_scan(path)
    if maybe_seq_id is None:
        # Not a Swift scan
        return False

    if seq_id != "" and maybe_seq_id != seq_id:
        # Sequence ID does not match
        return False

    if os.path.isdir(path):
        return os.path.exists(os.path.normpath(os.path.join(path, SWIFT_HASH_LIST)))
    else:
        return ole_contains_stream(path, SWIFT_HASH_LIST)

def find_last_scan_in_sequence(root_path: str, seq_id: str) -> typing.Optional[str]:
    """ Iterates over contents of @p root_path and returns the
        name (= path relative to @p root_path) of the final scan
        belonging to a given Swift sequence, if such scan is contained in @p root_path.
        If no such scan is found, `None` is returned.
    """
    if not os.path.isdir(root_path):
        logger.warning("Root path '%s' is not a folder!", root_path)
        return None
    for item in os.listdir(root_path):
        item_path = os.path.join(root_path, item)
        if is_last_scan_in_swift_seq(item_path, seq_id):
            logger.debug("Last scan in sequence: '%s'", item)
            return item
    return None


def scan_count(path, check_any=False) -> int:
    try:
        n_hashed_scans = 0
        directory_contents = os.listdir(path)
        for item in directory_contents:
            item_path = os.path.join(path, item)
            if is_hashed_scan(item_path) and not does_spl_exist(item_path):
                n_hashed_scans += 1
                if check_any:
                    return n_hashed_scans

        return n_hashed_scans
    except Exception:
        return 0


def is_hashed_scan(path) -> bool:
    is_scan = False

    if not os.path.isdir(path):
        try:
            if olefile.isOleFile(path):
                with olefile.OleFileIO(path) as ole:
                    is_scan = ole.exists(SUM_LEVEL1)
        except EnvironmentError as e:
            logger.warning("Error when opening OLE file {1}: {0}".format(str(e), path))
            is_scan = False
    else:
        try:
            is_scan = any(fname == SUM_LEVEL1 for fname in os.listdir(path))
        except EnvironmentError as e:
            logger.warning("Error when scanning folder contents: {0}".format(str(e)))
    return is_scan

def is_scan_v1_ole(scan: olefile.OleFileIO) -> bool:
    return scan.exists(MAIN_PARAM_STREAM) and scan.exists(SCANS_SUBFOLDER)

def is_scan_v2_ole(scan: olefile.OleFileIO) -> bool:
    return scan.exists(LSDATAV2_VERSION_FILE) and scan.exists(LSDATAV2_SCANDATA_SUBFOLDER)

def is_scan_v1_folder(path: str) -> bool:
    return os.path.exists(os.path.join(path, MAIN_PARAM_STREAM)) \
        and os.path.exists(os.path.join(path, SCANS_SUBFOLDER))

def is_scan_v2_folder(path: str) -> bool:
    return os.path.exists(os.path.join(path, LSDATAV2_VERSION_FILE)) \
        and os.path.exists(os.path.join(path, LSDATAV2_SCANDATA_SUBFOLDER))

def is_scan_folder(path: str) -> bool:
    if not os.path.isdir(path):
        return False

    try:
        return is_scan_v1_folder(path) or is_scan_v2_folder(path)
    except EnvironmentError as e:
        logger.warning("Error when scanning folder contents: {0}".format(str(e)))
    return False


def is_hashing_file(path):
    return (path in [SUM_LEVEL1, SUM_LEVEL2, SIGNATURE]) or Sfm.is_hash(path)


def is_valid_key(path):
    """ Check the validity of a RSA key
    :param str path: Path to the key file to be checked  
    :return: True if the path points to a key file containing a key 
            that can be used for verifying a RSA signature 
    :rtype: bool
    """
    logger.debug("Checking the validity of the key '%s'", path)
    rsakey = load_rsakey(path)
    return rsakey is not None and rsakey.can_sign()


def load_rsakey(path):
    """
    :return: An object representing the loaded RSA key
    :rtype: Crypto.PublicKey.RSA._RSAobj
    """
    try:
        pub_key = open(os.path.normpath(path), "r").read()
    except EnvironmentError:
        logger.warning("Could not open the key file")
        return None

    try:
        rsakey = RSA.importKey(pub_key)
        return rsakey
    except:
        logger.warning("Could not import the loaded key file contents")
        return None


class VerifierThread(QtCore.QThread):
    scan_checked = QtCore.pyqtSignal(VerificationResult)
    finished = QtCore.pyqtSignal()
    result_changed = QtCore.pyqtSignal(VerificationResult)

    def __init__(self, root_path, key_path, selected_scans: list = None, parent=None):
        super(VerifierThread, self).__init__(parent)
        self._signer = None
        self._root_path = root_path
        self._key_path = key_path
        self._selected_scans = selected_scans

        # scan names and their overall hashes
        self._swift_scan_hashes = {}

        if is_valid_key(self._key_path):
            self._init_signature_verifyer()

    def _init_signature_verifyer(self):
        pub_key = open(os.path.normpath(self._key_path), "r").read()
        logger.debug("Loaded public key for signature verification")
        rsakey = RSA.importKey(pub_key)

        self._signer = PKCS1_PSS.new(rsakey)

    def run(self):
        # scan plan project
        if does_spl_exist(self._root_path):
            self.verify_scanplan_project()

        # Freestyle raw scans
        elif Sfm.is_folder(self._root_path) or Sfm.is_file(self._root_path):
            self.verify_sfm()

        # scans folder
        else:
            self.verify_scans()  # emits scan_checked for every checked folder
        self.finished.emit()  # all folders checked

    def verify_scanplan_project(self, path=None):
        if path is None:
            path = self._root_path

        logger.info("Verifying scanplan project '{0}'".format(path))
        is_dir = os.path.isdir(path)

        item_result = VerificationResult(path, is_scanplan_project=True)

        if is_dir and (not any(fname == SUM_LEVEL1 for fname in os.listdir(path))):
            logger.info("Skipping (scan) {1} because not a hashed scan: {0}".format(path,
                                                                                    "folder" if is_dir else "file"))
            item_result.hash_result = HashResult.HASH_LIST_MISSING
            item_result.sign_result = SignatureResult.NO_HASH_FILE
            self.scan_checked.emit(item_result)

        else:
            logger.info("Verifying the hashes of the scan {1}: {0}".format(path,
                                                                           "folder" if is_dir else "file"))
            scan_to_verify = path
            hash_status = self.verify_hash_single_scan(scan_to_verify)
            item_result.hash_result = hash_status.get('total_hash_status', HashResult.FAILED)
            item_result.total_hash_calc = hash_status.get('total_hash_calc', '')
            item_result.total_hash_read = hash_status.get('total_hash_read', '')
            item_result.sub_hashes = hash_status.get('file_status', {})

            item_result.sign_result = self.verify_signature(scan_to_verify)  # SignatureResult.PASSED
            item_result.expected_hash = "PLEASE ENTER THE EXPECTED HASH OR CLEAR THIS FIELD"

            self.scan_checked.emit(item_result)

    def verify_sfm(self):
        for scan in Sfm.files(self._root_path):
            self.scan_checked.emit(Sfm.verify(scan, self._signer))

    def verify_scans(self):
        logger.debug("Verifying scans in '{0}'".format(self._root_path))
        try:
            if is_hashed_scan(self._root_path):
                # Verify single Scan
                self.verify_scan(self._root_path)
            else:
                # Verify directory with Scans
                selected_items = self._selected_scans
                if selected_items is None:
                    selected_items = os.listdir(self._root_path)
                for item in selected_items:
                    logger.debug("sub-item: %s", item)
                    sub_path = os.path.join(self._root_path, item)
                    if os.path.isdir(sub_path) and not is_scan_folder(sub_path):
                        # folder, but not a scan
                        logger.debug("folder, but not a scan: %s",  sub_path)
                        continue
                    self.verify_scan(sub_path)

        except EnvironmentError:
            logger.error("OS error when verifying the scans", exc_info=True)

    def handle_swift_results(self, hash_status: dict, item_result: VerificationResult):
        logger.debug("Handling a Focus Swift scan")
        is_swift_last = hash_status.get('swift_last_in_seq', False)
        item_result.is_swift_scan = True
        item_path = item_result.scan_path

        # this scan belongs to a sequence => store its hash for future
        seq_id = hash_status.get('swift_seq_id', '')
        self._swift_scan_hashes[item_path] = {'seq_id': seq_id,
                                              'hash': item_result.total_hash_calc,
                                              'summary': item_result.hash_result}

        # if verification was otherwise OK, mark as "sequence relation is not confirmed" until the last scan is checked
        # if this is the last one, the relation to the sequence is given by definition
        if not is_swift_last and item_result.hash_result == HashResult.PASSED:
            item_result.hash_result = HashResult.SWIFT_SEQ_UNCONFIRMED
        else:
            item_result.is_swift_last_scan = True

            if item_result.hash_result != HashResult.PASSED:
                logger.info("Skipping the verification of the Swift scan sequence "
                            + "because the last scan of the sequence failed the pre-swift verification")
                return

            if self._root_path == item_path:
                logger.info("Skipping the verification of the Swift scan sequence "
                            + "because a single scan has been selected for verification")
                item_result.hash_result = HashResult.SWIFT_SEQ_SCAN_MISSING
                return

            logger.debug("Last scan of a Swift sequence. Check all contained scans.")
            # this should only happen for one scan in a sequence.
            # For all others, we call this function recursively,
            # recursion depth will be not more than 1
            seq_hashes = hash_status.get('swift_seq_hashes', {})
            all_swift_scans_available = True
            all_swift_hashes_ok = True
            for (scan_name, scan_hash) in seq_hashes.items():
                # get the full path of a scan belonging to the same sequence
                is_dir = os.path.isdir(item_path)
                scan_full_path = get_path_to_other(item_path, is_dir, scan_name)

                # Verify the scan if not already done
                if scan_full_path not in self._swift_scan_hashes.keys():
                    logger.debug("Scan {} needs verification!".format(scan_name))
                    self.verify_scan(scan_full_path)

                # now, the scan must be in the saved list
                if scan_full_path not in self._swift_scan_hashes.keys():
                    logger.info("Scan belonging to a Swift sequence not found: " + scan_full_path)
                    all_swift_scans_available = False
                else:
                    logger.debug("Scan {} has been (meanwhile) verified.".format(scan_name))
                    seq_id_match = (hash_status.get('swift_seq_id', '')
                                    == self._swift_scan_hashes[scan_full_path].get('seq_id', ''))

                    # mark the scan as not SWIFT_SEQ_UNCONFIRMED anymore and notify the GUI
                    result_dummy = VerificationResult(scan_full_path)
                    result_dummy.is_swift_scan = True
                    result_dummy.is_swift_last_scan = False
                    original_summary = self._swift_scan_hashes[scan_full_path].get('summary', HashResult.FAILED)
                    # mark as SWIFT_SCAN_BAD_SEQ only if the non-Swift status would be OK otherwise
                    result_dummy.hash_result = (original_summary
                                                if seq_id_match or original_summary != HashResult.PASSED
                                                else HashResult.SWIFT_SCAN_BAD_SEQ)

                    self.result_changed.emit(result_dummy)

                    # if a scan claims to belong to another sequence,
                    # then the one belonging to this one is obviously not available
                    if not seq_id_match:
                        all_swift_scans_available = False

                    # mark scan mismatch if the scan has failed hash verification
                    # or its hash does not match the one saved in the list of sequence's scans
                    hash_match = (scan_hash == self._swift_scan_hashes[scan_full_path].get('hash', '')
                                  and (self._swift_scan_hashes[scan_full_path].get('summary', HashResult.FAILED)
                                       == HashResult.PASSED))
                    if not hash_match:
                        all_swift_hashes_ok = False

            if not all_swift_scans_available:
                item_result.hash_result = HashResult.SWIFT_SEQ_SCAN_MISSING
            elif not all_swift_hashes_ok:
                item_result.hash_result = HashResult.SWIFT_SEQ_HASH_MISMATCH

    def verify_scan(self, item_path):
        ole = None  # will be dereferenced in "finally", so we initialize the variable here
        try:
            if item_path in self._swift_scan_hashes.keys():
                # already verified and notified the GUI
                logger.debug("Scan {} already verified. Skipping a second verification".format(item_path))
                return
            is_dir = os.path.isdir(item_path)
            is_ole = (not is_dir) and (olefile.isOleFile(item_path))  # ".fls" in item_path and

            if is_ole:
                ole = olefile.OleFileIO(item_path)

            if is_dir and does_spl_exist(item_path):
                self.verify_scanplan_project(item_path)
                # Just to be sure. this should not happen
                return

            dirs = None
            if is_dir:
                try:
                    dirs = os.listdir(item_path)
                except PermissionError:
                    logger.warning("No permission to access: {}".format(item_path))
                    return

            if is_dir or is_ole:
                item_result = VerificationResult(item_path)
                if (is_dir and (not any(fname == SUM_LEVEL1 for fname in dirs))) \
                        or (is_ole and (not ole.exists(SUM_LEVEL1))):
                    logger.debug("Skipping (scan) {1} because not a hashed scan: {0}".format(item_path,
                                                                                             "folder" if is_dir else "file"))
                    item_result.hash_result = HashResult.HASH_LIST_MISSING
                    item_result.sign_result = SignatureResult.NO_HASH_FILE
                else:
                    logger.debug("Verifying the hashes of the scan {1}: {0}".format(item_path,
                                                                                    "folder" if is_dir else "file"))
                    scan_to_verify = item_path if is_dir else ole
                    hash_status = self.verify_hash_single_scan(scan_to_verify)
                    item_result.hash_result = hash_status.get('total_hash_status', HashResult.FAILED)
                    item_result.total_hash_calc = hash_status.get('total_hash_calc', '')
                    item_result.total_hash_read = hash_status.get('total_hash_read', '')
                    item_result.sub_hashes = hash_status.get('file_status', {})
                    item_result.sign_result = self.verify_signature(scan_to_verify)  # SignatureResult.PASSED

                    if hash_status.get('swift_scan', False):
                        # this  function will also initiate the verification of other scans
                        # belonging to the sequence if needed
                        self.handle_swift_results(hash_status, item_result)

                self.scan_checked.emit(item_result)
            else:
                logger.debug("Not a dir and not an OLE file: {0}".format(item_path))

        except Exception as ex:
            logger.error("Exception: {}".format(ex))

        finally:
            if ole is not None:
                ole.close()

    def verify_hash_single_scan(self, scan) -> dict:
        hash_lines = []
        total_hash_read = ''
        is_ole = False
        try:
            if isinstance(scan, str):
                hash_lines = [line.rstrip('\n') for line in open(os.path.join(scan, SUM_LEVEL1))]
                total_hash_read = [line.rstrip('\n') for line in open(os.path.join(scan, SUM_LEVEL2))][0]
            elif isinstance(scan, olefile.OleFileIO):
                for line in scan.openstream(SUM_LEVEL1):
                    hash_lines.append(line.decode('ASCII').rstrip('\n'))
                for line in scan.openstream(SUM_LEVEL2):
                    total_hash_read = line.decode('ASCII').rstrip('\n')
                is_ole = True
            else:
                raise TypeError("A string or a open OleFileIO object is expected!")
        except EnvironmentError as ex:
            logger.warning("Error: {}".format(ex))

        hash_status = {'total_hash_calc': '',
                       'total_hash_read': total_hash_read,
                       'total_hash_status': HashResult.FAILED,
                       'file_status': {},
                       'swift_scan': False,
                       'swift_seq_id': '',
                       'swift_last_in_seq': False,
                       'swift_seq_hashes': {}}

        # if the hash fails for any file, this will be set to True
        file_hash_mismatch = False
        total_scan_hasher = hashlib.sha256()
        for hash_line in hash_lines:
            item = hash_line.split(' ')
            filename = item[1].strip('*')
            hash_read = item[0].upper()

            file_status = HashedFileInfo(scan_path=scan,
                                         relative_path=filename,
                                         is_dir=False,
                                         hash_read=hash_read)
            try:
                if is_ole:
                    if filename == ".classid":
                        hash_calc = hash_data(CLASSID).upper()
                    elif '.fls' in filename:
                        hash_calc = hash_data(b'').upper()
                    else:
                        hash_calc = hash_file(scan.openstream(filename)).upper()
                else:
                    hash_calc = hash_file(os.path.normpath(os.path.join(scan, filename))).upper()

                if filename == SWIFT_SEQ_ID:
                    hash_status['swift_scan'] = True
                    hash_status['swift_seq_id'] = extract_swift_seq_id(
                        scan.openstream(filename) if is_ole else os.path.normpath(os.path.join(scan, filename)))
                if filename == SWIFT_HASH_LIST:
                    hash_status['swift_last_in_seq'] = True
                    hash_status['swift_seq_hashes'] = read_swift_hash_list(
                        scan.openstream(filename) if is_ole
                        else os.path.normpath(os.path.join(scan, filename)))

                file_status.file_present = True
                file_hash_match = (hash_calc == hash_read)
                file_status.hash_ok = file_hash_match
                file_status.hash_calc = hash_calc
                if not file_hash_match:
                    file_hash_mismatch = True  # save for checking later
                ha = "{} *{}\n".format(hash_calc, filename)
                total_scan_hasher.update(ha.encode('utf-8'))

            except (EnvironmentError, IOError):
                file_status.file_present = False
                file_status.hash_ok = False
                hash_status['total_hash_status'] = HashResult.HASHED_FILE_MISSING
            hash_status['file_status'][filename] = file_status

        if isinstance(scan, str) and is_scan_v2_folder(scan):
            """ In addition to the files listed in `SUM_LEVEL1`, we check that
                a file named like the scan folder exists in this folder and is empty.
                In data format v2, this file is not included in `SUM_LEVEL1` anymore.
            """
            _, fls_file_name = os.path.split(scan)
            file_status = HashedFileInfo(scan_path=scan,
                            relative_path=fls_file_name,
                            is_dir=False,
                            hash_read="EXPECTED_TO_BE_EMPTY")
            if os.path.exists(os.path.join(scan, fls_file_name)):
                file_status.file_present = True
                if len(open(os.path.join(scan, fls_file_name)).read()) == 0:
                    file_status.hash_calc = "FOUND_EMPTY_OK"
                    file_status.hash_ok = True
                else:
                    file_status.hash_calc = "FOUND_NOT_EMPTY"
                    file_hash_mismatch = True
            else:
                hash_status['total_hash_status'] = HashResult.HASHED_FILE_MISSING
            hash_status['file_status'][fls_file_name] = file_status

        total_hash_calc = total_scan_hasher.hexdigest().upper()
        hash_status['total_hash_calc'] = total_hash_calc

        # Finalize the overall hash status
        logger.info("Hash verification for scan '%s':", "<OLE>" if is_ole else scan)
        if not (hash_status['total_hash_status'] == HashResult.HASHED_FILE_MISSING):
            if file_hash_mismatch:
                logger.info("Hash verification failed for at least one file")
                hash_status['total_hash_status'] = HashResult.FILE_HASH_FAILED
            elif len(total_hash_read) == 0:
                logger.info("Overall hash checksum file for this scan is missing")
                hash_status['total_hash_status'] = HashResult.HASH_TOTAL_MISSING
            elif not (total_hash_read == total_hash_calc):
                logger.info("Verification of the overall hash checksum for this scan failed")
                hash_status['total_hash_status'] = HashResult.TOTAL_HASH_FAILED
            else:
                logger.info("Everything OK")
                hash_status['total_hash_status'] = HashResult.PASSED
        else:
            logger.info("Not a scan or the hash list file is missing")

        return hash_status

    @staticmethod
    def format_hexstr(bytearr) -> str:
        retval = "".join("{:02x}".format(x) for x in bytearr)
        return "\n".join(textwrap.wrap(retval, 80))

    def verify_signature(self, scan):
        """
            
        """
        try:
            if len(self._key_path) == 0:
                logger.warning("Skip signature verification because no key available")
                return SignatureResult.NO_KEY_PROVIDED

            if self._signer is None:  # not is_valid_key(self._key_path):
                logger.warning("Skip signature verification due to invalid key")
                return SignatureResult.INVALID_KEY

            # Load signature and hash_file_data
            hash_file_data = None
            signature = None
            try:
                if isinstance(scan, str):
                    signature = open(os.path.join(scan, SIGNATURE), "rb").read()
                    hash_file_data = open(os.path.join(scan, SUM_LEVEL1), "rb").read()
                elif isinstance(scan, olefile.OleFileIO):
                    signature = scan.openstream(SIGNATURE).read()
                    hash_file_data = scan.openstream(SUM_LEVEL1).read()
                else:
                    raise TypeError("A string or a open OleFileIO object is expected!")
                logger.info("Loaded scan signature: \n{}".format(self.format_hexstr(signature)))
            except (EnvironmentError, IOError):
                logger.warning("Abort: Scan contains no signature file or no hash list file")

            if signature is None:
                return SignatureResult.NO_SIGN_FILE
            if hash_file_data is None:
                return SignatureResult.NO_HASH_FILE

            digest = None
            if (isinstance(scan, str) and is_scan_v1_folder(scan)) \
                    or (isinstance(scan, olefile.OleFileIO) and is_scan_v1_ole(scan)):
                logger.debug("Will check signature on a scan data format V1")
                digest = cryptoSHA.new()
            elif (isinstance(scan, str) and is_scan_v2_folder(scan)) \
                    or (isinstance(scan, olefile.OleFileIO) and is_scan_v2_ole(scan)):
                logger.debug("Will check signature on a scan data format V2")
                digest = cryptoSHAv2.new()

            if digest is None:
                logger.error("Skip signature verification: Unknown scan format")
                return SignatureResult.HASH_CALC_FAILED

            # Verify Signature
            digest.update(hash_file_data)
            if self._signer.verify(digest, signature):
                return SignatureResult.PASSED
            else:
                return SignatureResult.HASH_FILE_FAILED
        except Exception as ex:
            logging.exception("Exception in verify_signature: {}".format(ex))
            return SignatureResult.HASH_FILE_FAILED
