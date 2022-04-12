"""
This module provides definitions of path constants for keys to be used for signature verification.
"""
import os

KEY_FOLDER = os.path.normpath('./keys')
KEY_FILE_V1 = 'FARO_scan_signature_key.pem'
KEY_FILE_V2 = 'FARO_scanV2_signature_key.pem'
KEY_PATH = os.path.join(KEY_FOLDER, KEY_FILE_V1)
KEY_PATH_V2 = os.path.join(KEY_FOLDER, KEY_FILE_V2)
