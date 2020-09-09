"""
Copyright (C) 2018 FARO Technologies Inc.
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License
version 3 or (at your option) any later version as published by the Free Software Foundation
and appearing in the file LICENSE included in the packaging of this file.

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This file defines the UI and behavior of the file system view onto the files being verified.
"""

from typing import Union

from PyQt5 import QtGui, QtSvg
from PyQt5.QtCore import Qt

from .functions import *
from .verification_algorithms import *

HDR_NAME = 0
HDR_DATE = 1
HDR_STATUS = 2

logger = logging.getLogger(__name__)


# noinspection PyCallByClass
class FileSystemHashModel(QtWidgets.QFileSystemModel):
    """ Provides a mapping between the file system entries and verification results
        Overrides some functions of QFileSystemModel
    """
    # The enumeration of HashModel-specific data roles
    # To avoid collision with Qt.ItemDataRole (int), we use another data type (string)
    HashDataRole = 'hash_result'
    isScanPlanProject = True

    def __init__(self):
        super(FileSystemHashModel, self).__init__()
        self.icon_src = {
            'failed': [get_icon_path("close-circle.svg"), 0x00000000],
            'passed': [get_icon_path("checkbox-marked-circle.svg"), 0x00000000],
            'unknown': [None, 0x00000000],
            'cert': [get_icon_path("certificate.svg"), 0x00000000],
            'warning': [get_icon_path("help-circle.svg"), 0x00000000],
            'folder': [get_icon_path("folder.svg"), 0x00000000]
        }

        self._icons = {}
        self._load_icons()
        self._status_data = {}

    def _load_icons(self):
        for key in self.icon_src.keys():
            self._icons[key] = self._load_icon(self.icon_src[key][0], self.icon_src[key][1])

    def _load_icon(self, path, bg_color=0x10808080):
        base_image = QtGui.QImage(24, 24, QtGui.QImage.Format_ARGB32)
        base_image.fill(bg_color)

        # create the icon pixmap:
        QtSvg.QSvgRenderer(path).render(QtGui.QPainter(base_image))
        pixmap = QtGui.QPixmap.fromImage(base_image)
        return pixmap

    def columnCount(self, parent=QtCore.QModelIndex()):
        """ overridden from QFileSystemModel
        """
        return 3  # super(FileSystemHashModel, self).columnCount(parent) + 1

    def _get_scan_check_details(self, check_status):
        if check_status is None:
            return "Unknown"
        else:
            return check_status.get_str(False)

    def scan_for_file(self, file_index, max_depth=1000):
        index = file_index
        selected_path = os.path.normpath(str(self.filePath(file_index)))
        if is_hashed_scan(selected_path):
            # already a scan folder
            return file_index

        index = index.parent()
        search_depth = 1

        while index.isValid() and search_depth <= max_depth:
            current_path = os.path.normpath(str(self.filePath(index)))
            if is_hashed_scan(current_path):
                return index
            search_depth += 1
            index = index.parent()

        return None

    def get_verification_result_from_index(self, data_index) -> VerificationResult:
        # The selected item is not a hashed scan. But maybe it is part of a scan?
        scan_for_file = self.scan_for_file(data_index, max_depth=3)
        if scan_for_file is None:
            # no, the selected item is not part of a scan
            return None

        # we have the scan containing the selected file.
        # Get the details of the file
        scan_path = os.path.normpath(str(self.filePath(scan_for_file)))
        verification_result: VerificationResult = self.get_verification_result(scan_path)
        return verification_result

    def get_verification_result(self, scan_path) -> VerificationResult:
        for current in list(self._status_data.values()):
            if scan_path == current.scan_path:
                return current

    @staticmethod
    def get_project_tooltip(result) -> str:
        if result.hash_result == HashResult.HASH_LIST_MISSING:
            tooltip = "SHA256SUM is missing"
        elif result.hash_result == HashResult.HASH_TOTAL_MISSING:
            tooltip = "SHA256SUM.sha is missing"
        elif result.sign_result == SignatureResult.NO_SIGN_FILE:
            tooltip = "SHA256SUM.sig is missing"
        elif result.is_scanplan_project:
            if result.hash_result == HashResult.PASSED and \
                    result.sign_result == SignatureResult.PASSED:
                if result.expected_hash_result == HashResult.PASSED:
                    tooltip = "Hash and Signature validation PASSED and Expected Hash matches"
                elif result.expected_hash_result == HashResult.FAILED:
                    tooltip = "Hash and Signature validation PASSED but Expected Hash FAILED"
                else:
                    tooltip = "Hash and Signature validation PASSED"
            else:
                tooltip = "Failed validation. For more information, see the report."
        else:
            if result.hash_result == HashResult.PASSED and \
                    result.sign_result == SignatureResult.PASSED:
                tooltip = "Hash and Signature validation PASSED"
            else:
                tooltip = "Failed validation. For more information, see the report."

        return tooltip

    def get_project_icon(self, result):

        if result.is_scanplan_project:
            if result.hash_result == HashResult.PASSED and \
                    result.sign_result == SignatureResult.PASSED:
                if result.expected_hash_result == HashResult.PASSED:
                    ret_icon = self._icons['passed']
                elif result.expected_hash_result == HashResult.FAILED:
                    ret_icon = self._icons['failed']
                else:
                    ret_icon = self._icons['passed']
            else:
                ret_icon = self._icons['failed']

        else:
            if result.hash_result == HashResult.PASSED and \
                    result.sign_result == SignatureResult.PASSED:
                ret_icon = self._icons['passed']
            elif result.hash_result == HashResult.SWIFT_SEQ_UNCONFIRMED:
                ret_icon = self._icons['warning']
            else:
                ret_icon = self._icons['failed']

        return ret_icon

    def data(self, index, role=Qt.DisplayRole) -> [Union[VerificationResult, HashedFileInfo, None]]:
        """ overridden from QFileSystemModel
        """

        if role == FileSystemHashModel.HashDataRole:
            # make sure we use the correct index for retrieving the data:
            if index.column() == HDR_NAME:
                data_index = index.sibling(index.row(), HDR_STATUS)
            else:
                data_index = index

            file_path = os.path.normpath(str(self.filePath(data_index)))

            # The selected item is not a hashed scan. But maybe it is part of a scan?
            scan_for_file = self.scan_for_file(data_index, max_depth=3)
            if scan_for_file is None:
                # no, the selected item is not part of a scan
                return None

            # we have the scan containing the selected file.
            # Get the details of the file
            scan_path = os.path.normpath(str(self.filePath(scan_for_file)))
            relative_path = os.path.relpath(file_path, scan_path)
            verification_result = self.get_verification_result(scan_path)

            file_info = None
            if verification_result is not None:
                assert isinstance(verification_result, VerificationResult)
                file_info = verification_result.sub_hashes.get(relative_path.replace('\\', '/'), None)
                if relative_path == ".":
                    # Return VerificationResult for Scan Path
                    return verification_result
                if file_info is None:
                    note = "This file does not belong to the project or scan."
                    if is_hashing_file(relative_path):
                        note = "Secure Hash Algorithm (SHA-256) file."
                    # This entry was not in the hash list => create a new file info object
                    file_info = HashedFileInfo(scan_path=scan_path,
                                               relative_path=relative_path.replace('\\', '/'),
                                               is_dir=os.path.isdir(file_path),
                                               file_present=True,
                                               hash_ok=False,
                                               note=note)
            return file_info

        # other roles are either handled by this class or by the superclass within Qt
        elif index.isValid() and index.column() == HDR_STATUS:
            # The data for column 2 is stored by this class
            check_status = self._status_data.get(index, None)
            index_path = self.filePath(index)
            if role == Qt.DecorationRole:
                ret_icon = self._icons['unknown']

                # For Scan Folder
                if check_status is not None:
                    ret_icon = self.get_project_icon(check_status)
                else:
                    # This might be a processed file inside a scan.
                    file_status = self.data(index, FileSystemHashModel.HashDataRole)
                    if file_status is not None:
                        if isinstance(file_status, HashedFileInfo):
                            if file_status.is_dir:
                                ret_icon = self._icons['folder']
                            elif is_hashing_file(file_status.relative_path):
                                ret_icon = self._icons['cert']
                            elif len(file_status.hash_read) == 0:
                                # file present but not contained in the has list!
                                ret_icon = self._icons['warning']
                            elif file_status.hash_ok:
                                ret_icon = self._icons['passed']
                            else:
                                ret_icon = self._icons['failed']
                        elif isinstance(file_status, VerificationResult):
                            ret_icon = self.get_project_icon(file_status)
                return ret_icon

            elif role in [Qt.StatusTipRole, Qt.ToolTipRole]:
                # For Scan Folder
                tooltip = "unknown"
                if check_status is not None:
                    tooltip = self.get_project_tooltip(check_status)
                else:
                    # This might be a processed file inside a scan.
                    file_status = self.data(index, FileSystemHashModel.HashDataRole)
                    if file_status is not None:
                        if isinstance(file_status, HashedFileInfo):
                            if file_status.is_dir:
                                tooltip = None
                            elif is_hashing_file(file_status.relative_path):
                                tooltip = "Certificate file"
                            elif len(file_status.hash_read) == 0:
                                # file present but not contained in the has list!
                                tooltip = "This file does NOT belong to the project!"
                            elif file_status.hash_ok:
                                tooltip = "File Hash is OK"
                            else:
                                tooltip = "File Hash FAILED!"
                        elif isinstance(file_status, VerificationResult):
                            tooltip = self.get_project_tooltip(file_status)
                return tooltip
            else:
                return None

        elif index.isValid() and index.column() == HDR_DATE:
            # Todo: return DATE for SCAN folders
            return None
        else:
            # delegate to superclass
            return super(FileSystemHashModel, self).data(index, role)

    def setData(self, index, data: VerificationResult, role=Qt.EditRole):
        """ overridden from QFileSystemModel
        """
        if index.isValid() and index.column() == HDR_STATUS:
            self._status_data[index] = data
            self.dataChanged.emit(index, index)
        else:
            self._status_data[index] = data
            self.dataChanged.emit(index, index)
            super(FileSystemHashModel, self).setData(index, data, role)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        """ overridden from QFileSystemModel
        """
        if section == HDR_NAME:

            return super(FileSystemHashModel, self).headerData(section, orientation, role)
        elif section == HDR_DATE:

            if role in [Qt.WhatsThisRole, Qt.ToolTipRole]:
                return "Last modification or record date"
            else:
                return "Last Modified"
        elif section == HDR_STATUS:
            if role in [Qt.WhatsThisRole, Qt.ToolTipRole]:
                return "Shows the Hash/Signature verification status"
            else:
                return "Status"
