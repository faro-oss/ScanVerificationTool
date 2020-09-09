"""
Copyright (C) 2018 FARO Technologies Inc. 
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License 
version 3 or (at your option) any later version as published by the Free Software Foundation 
and appearing in the file LICENSE included in the packaging of this file.  

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This file defines the UI and behavior of the main window of the verification tool.
"""

import platform
import urllib
import json
import subprocess
import os
from threading import Lock
from .version_parser import Version

from PyQt5 import QtGui
from PyQt5.QtCore import Qt, QSettings, PYQT_VERSION_STR, QT_VERSION_STR

from ui_gen.ui_layout import Ui_MainWindow
from .file_system_hash_model import FileSystemHashModel, HDR_NAME, HDR_DATE, HDR_STATUS
from .functions import *
from .report_dialog import ReportDialog
from .verification_algorithms import *

"""
for GUI
ui_layout is generated from the QtDesigner file hash_verify.ui
python -m PyQt5.uic.pyuic -x src/hash_verify.ui -o src/ui_layout.py
python -m PyQt5.uic.pyuic -x src/report_dialog.ui -o src/ui_report_dialog.py
"""

STATUSBAR_MSG_DURATION = 4000  # in milliseconds
logger = logging.getLogger(__name__)

"""
Colors used in the project:
===========================
light gray: #acacac
dark gray:  #3c3c3c
faro blue:  #005096
pressed:    #83b2da
hover:      #add2f0
green:      #00be00
red:        #d20000
disabled:   #898989 Mac: #7fa7cd
"""


# noinspection PyCallByClass
class Verify(QtWidgets.QMainWindow, Ui_MainWindow):
    """ Defines the behavior of the main UI window.
    """
    open_scan_request = QtCore.pyqtSignal()
    open_key_request = QtCore.pyqtSignal()
    key_invalid = QtCore.pyqtSignal()

    def __init__(self, app, key_path="", version="0.0.0.0"):
        QtWidgets.QMainWindow.__init__(self)
        self._is_scan_plan = False
        self._app = app
        self._root_path = ""
        self._selected_path = ""
        self._key_path = ""
        self._version = version
        self.current_verification_result = None
        self.is_verify = False

        self.setupUi(self)

        # Setup settings
        self.settings = QSettings('settings.ini', QSettings.IniFormat)

        # Setup Window Properties
        self._set_app_icon()
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.key_details_action.setDisabled(True)
        self._goto_drop_page()

        # Setup drop Lines
        self.drop_lines = [self.line_f1, self.line_f2, self.line_f3, self.line_f4]
        self.drop_lines_verify = [self.line_v1, self.line_v2, self.line_v3, self.line_v4]

        # Colors
        self.COLOR_DROP = "#83b2da"
        self.COLOR_FARO_BLUE = "#005096"
        self.COLOR_DARK_GRAY = "#3c3c3c"

        # HTML styles
        self.style_blue = " style='color: {};' ".format(self.COLOR_FARO_BLUE)
        self.style_gray = " style='color: {};' ".format(self.COLOR_DARK_GRAY)

        if not is_valid_key(key_path):
            self._display_key_path()
            # display the warning after GUI has been displayed (100ms after 'now')
            QtCore.QTimer.singleShot(100, self.key_invalid.emit)

        else:
            self.key_details_action.setDisabled(False)
            self._key_path = key_path
            self._display_key_path()

        self._worker = None  # There will be only one at a time!
        self._working = False
        self._working_lock = Lock()

        # Setup Tree View
        model = FileSystemHashModel()  # QtGui.QFileSystemModel()

        self.folder_tree.setModel(model)
        self.folder_tree.setColumnWidth(HDR_DATE, 140)
        self.folder_tree.setColumnWidth(HDR_STATUS, 40)
        self.folder_tree.setColumnWidth(HDR_NAME, 544)
        self.folder_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.folder_tree.customContextMenuRequested.connect(self.tree_context_menu)

        # Setup Signals and Slots
        self.lineEdit_expectedHash.textChanged.connect(self.expected_hash_changed)
        self.folder_tree.selectionModel().selectionChanged.connect(self.tree_selection_changed)
        self.btn_dir_up.clicked.connect(self.tree_cd_up)

        # Setup root
        self.__set_root_path(self._root_path)
        logger.info("Started the app with following settings:\nRoot path: '%s'\nKey path: '%s'",
                    self._root_path, self._key_path)

        # Add Version Info right of statusbar
        self.statusbar_version = QtWidgets.QLabel()
        self.statusbar.addPermanentWidget(self.statusbar_version)
        self.statusbar_version.setText("v{}".format(self._version))
        self.statusbar_version.setStyleSheet("color: #acacac;")

        # todo: Until it is implemented, clear text
        self.lbl_date.setText("")

        if platform.system() == "Darwin":
            self.__setup_macos()

    def __setup_macos(self):
        # Folder Tree
        self.folder_tree.setColumnWidth(HDR_DATE, 120)
        self.folder_tree.setColumnWidth(HDR_STATUS, 40)
        self.folder_tree.setColumnWidth(HDR_NAME, 436)

        self.statusbar.setStyleSheet("background: #efefef; color: #acacac;")

    def show_statusbar_message(self, msg):
        self.statusbar.showMessage(msg, STATUSBAR_MSG_DURATION)

    def lineEdit_expectedHash_setText(self, text):
        text = str(text).upper()
        cursor_pos = self.lineEdit_expectedHash.cursorPosition()
        self.lineEdit_expectedHash.setText(text)
        self.lineEdit_expectedHash.setCursorPosition(cursor_pos)

    def expected_hash_changed(self, text):
        """ pyQt slot

        """
        if text != text.upper():
            self.lineEdit_expectedHash_setText(text)
            return

        if self.current_verification_result is not None:
            if isinstance(self.current_verification_result, VerificationResult):
                if self.current_verification_result.is_scanplan_project:
                    self.current_verification_result.expected_hash = str(text)
                    self.set_current_project(self.current_verification_result)

    def __set_root_path(self, root_path):
        self.set_current_project(None)
        self._root_path = root_path
        self._root_index = self.folder_tree.model().setRootPath(self._root_path)
        self.folder_tree.setRootIndex(self._root_index)
        self.selected_project.setText(self._root_path)
        self.check_is_verify(self._root_path == "")
        self.btn_dir_up.setEnabled(self._root_path != "")

    def _set_app_icon(self):
        # Load the new Icon
        app_icon = QtGui.QIcon(get_icon_path("verify.ico"))
        self._app.setWindowIcon(app_icon)

    def _display_key_path(self):
        width_limit = 300
        metrics = self.fontMetrics()

        if len(self._key_path) == 0:
            logger.debug("No key path to display")
            return

        path_to_display = os.path.abspath(self._key_path)
        path_width = metrics.boundingRect(path_to_display).width()

        if path_width > width_limit:
            # the full path does not fit into the available space
            head1, filename = os.path.split(path_to_display)
            name_only_str = os.path.join('...', filename)
            path_to_display = name_only_str
            if len(head1) == 0:
                # the filename seems to be that long. Display name_only_str from above
                logger.info('Key file name too long for display')
            else:
                head_next, folder = os.path.split(head1)
                sub_path = os.path.join('...', folder, filename)
                path_width = metrics.boundingRect(sub_path).width()
                if len(head_next) > 0 and path_width <= width_limit:
                    # there is something to cut off and the sub-path fits into the limit
                    path_to_display = sub_path
                else:
                    logger.info('Key file name with last folder too long for display')

        logger.debug("Displaying key path '%s'", path_to_display)

    def _set_scan_plan_project(self, on):
        self._is_scan_plan = on
        self.scan_plan_box.setVisible(on)

    def show_manual(self):
        logger.debug("Showing Manual")
        manual = ""
        try:
            manual = self.get_manual("Faro_scan_verification_tool.pdf")
            if hasattr(os, 'startfile'):
                os.startfile(manual)
            else:
                subprocess.call(['/usr/bin/open', '-a', 'Preview', manual])
        except Exception as ex:
            logger.error("Error opening manual: {} in {}".format(ex, manual))
            self.show_statusbar_message("Could not find the manual in {}".format(manual))

    def check_for_updates(self):
        self.check_update(True)

    def check_update(self, always_show_message=False):
        try:
            system = platform.system()
            if system == "Windows":
                folder = "win"
            elif system == "Darwin":
                folder = "mac"
            else:
                self.show_statusbar_message("No update available for System: {}".format(system))
                return

            url = 'https://farofirmware.websharecloud.com/scan-verification-tool/{}/update.json'.format(folder)
            response = urllib.request.urlopen(url)
            data = response.read()  # a `bytes` object
            text = data.decode('utf-8-sig')  # 'utf-8-sig' also reads files with BOMs
            update_obj = json.loads(text)

            new_version = update_obj['version']
            if Version(new_version) > Version(self._version):
                self.show_statusbar_message("New Version available: {}".format(new_version))
                show_message(self, "<h1 {}>Update Available</h1>".format(self.style_blue) +
                             "<h2 {}>{}<br>".format(self.style_gray, update_obj['app']) +
                             "Version: {}</h2>".format(new_version) +
                             ("<div>{}</div>".format(
                                 update_obj['features_html']) if 'features_html' in update_obj else "") +
                             "<p><a {} href='{}'>Download Update</a></p>".format(self.style_blue, update_obj['file']) +
                             "<p><a {} href='{}'>Visit Website</a></p>".format(self.style_blue, update_obj['web']))
                return False
            else:
                self.show_statusbar_message("Up to date.")
                if always_show_message:
                    show_message(self, "<h1 {}>Up to date</h1>".format(self.style_blue) +
                                 "<h2 {}>{}<br>".format(self.style_gray, update_obj['app']) +
                                 "Version: {}</h2>".format(self._version) +
                                 "<p>You already have the latest version installed.")
                return True

        except json.decoder.JSONDecodeError as ex:
            error = "Error decoding update.json: {}".format(ex)
        except urllib.error.HTTPError as ex:
            error = "Error checking for update: {}".format(ex)
        except urllib.error.URLError as ex:
            error = "No internet? Could not check for update: {}".format(ex.reason)
        except Exception as ex:
            error = "Error checking for update: {}".format(ex)

        self.show_statusbar_message(error)
        if always_show_message:
            show_message(self, "<h1 {}>Update Check</h1>".format(self.style_blue) +
                         "<p>Could not check for an update.</p>"
                         "<p>Reason: {}</p>".format(error))

    def tree_context_menu(self, position):
        """ pyQt Slot  right click on tree view
        """
        indexes = self.folder_tree.selectedIndexes()
        if len(indexes) == 0:
            logger.debug("Nothing selected for the context menu")
            return

        index = indexes[0]

        selected_path = os.path.normpath(str(self.folder_tree.model().filePath(index)))
        logger.info("Context menu for the path '%s'", selected_path)

        menu = QtWidgets.QMenu()

        is_dir = os.path.isdir(selected_path)

        if is_dir:
            # ScanPlan Verify Action
            if does_spl_exist(selected_path):
                self._selected_path = selected_path
                menu.addAction(self.check_here_scanplan_action)
            # Scan Verify Action
            elif is_scan_verifyable(selected_path):
                self._selected_path = selected_path
                menu.addAction(self.check_here_action)

            # Show Report Action
            if self.folder_tree.model().data(index, FileSystemHashModel.HashDataRole) is not None:
                menu.addAction(self.verification_report)

        elif is_hashed_scan(selected_path):
            # Scan Verify Action for ole-file
            if is_scan_verifyable(selected_path):
                self._selected_path = selected_path
                menu.addAction(self.check_here_action)

            # Show Report Action
            if self.folder_tree.model().data(index, FileSystemHashModel.HashDataRole) is not None:
                menu.addAction(self.verification_report)

        if len(menu.actions()) > 0:
            menu.exec_(self.folder_tree.viewport().mapToGlobal(position))

    def _set_working_status(self, status):
        self.open_folder_btn.setDisabled(status)
        self.open_folder_btn_2.setDisabled(status)
        self.change_root_action.setDisabled(status)
        self.check_root_button.setDisabled(status)
        # TODO: somehow visualize the working process
        if status:
            pass
        else:
            pass

    def about_dialog(self):
        """ pyQt slot
        """
        logger.debug("Displaying the about dialog.")
        QtWidgets.QMessageBox.about(self,
                                    "About FARO Scan Verification Tool",
                                    "<h2 {}>FARO Scan Verification Tool</h2>".format(self.style_blue) + \
                                    "<h3 {}>Version: {}</h3>".format(self.style_gray, self._version) + \
                                    "<p>Copyright &copy; 2018-2019<br>"
                                    "FARO Technologies Inc.<br>"
                                    "All rights reserved in accordance<br>"
                                    "with GPL v3 or later.</p>"
                                    "<h3 {}>Used resources/libraries:</h3>".format(self.style_gray) + \
                                    "<p>Running with Python {}<br>".format(platform.python_version()) + \
                                    "GUI framework: Qt {} - PyQt {}<br>".format(QT_VERSION_STR, PYQT_VERSION_STR) + \
                                    "Icons: <a {} href='https://materialdesignicons.com'>Material Design Icons</a><br>".format(
                                        self.style_blue) + \
                                    "Cryptography: <a {} href='https://pycryptodome.readthedocs.io'>PyCryptodome</a></p>".format(
                                        self.style_blue))

    def back_btn_clicked(self):
        """ pyQt slot
        """
        self.__set_root_path("")
        self._goto_drop_page()

    def show_drives(self):
        self.__set_root_path("")
        self._goto_verify_page()

    def go_drop(self):
        self.back_btn_clicked()

    def _goto_drop_page(self):
        self.stackedWidget.setCurrentIndex(0)

    def _goto_verify_page(self):
        self.stackedWidget.setCurrentIndex(1)
        self.folder_tree.setFocus()

    def open_root(self, skip_verification=False, new_root=None):
        """ pyQt slot
        """
        logger.debug("Open Folder with Scans or ScanPlanProject")
        with self._working_lock:
            if self._working:
                # this should not appear because the action should be disabled.
                # If we get here somehow, don't display a dialog, cause it may deadlock
                logger.info("Refusing to open another scan folder. Please wait till the current one is checked.")
                return

        if new_root is None:
            if self._root_path == "":
                path = self.settings.value("default_path", "")
            else:
                path = self._root_path

            new_root = str(
                QtWidgets.QFileDialog.getExistingDirectory(self, caption="Open Folder with Scans or a ScanPlan Project",
                                                           directory=path))
        if len(new_root) == 0:
            logger.debug("User cancelled scan path selection dialog")
            return

        new_root = os.path.normpath(new_root)
        logger.debug("Selected root folder: '%s'", new_root)

        # Save as new default_path
        self.settings.setValue("default_path", new_root)

        if does_spl_exist(new_root):
            # todo: save expected hash and reuse it?
            pass

        else:
            ''' Handle Focus Scans '''
            # save the number for the (TODO:) progress calculation
            # n_scans_in_root = scan_count(new_root)

            if not is_scan_verifyable(new_root):
                message = "There are no sub folders with hashed scans in the selected folder: \n'{0}'".format(new_root)
                logger.info(message)
                retval = show_message(self, "The selected folder does not contain any signed FARO Focus Scans\n" +
                                      "or a ScanPlan Project.",
                                      icon=QtWidgets.QMessageBox.Information,
                                      additional="Do you want to look for another path?", yesno=True)
                if retval == QtWidgets.QMessageBox.Yes:
                    logger.debug("We should open another folder")
                    self.open_scan_request.emit()
                else:
                    logger.debug("Answer was not Yes (%s). We should NOT open another folder",
                                 QtWidgets.QMessageBox.Yes)
                return

            self._set_scan_plan_project(False)

        # Goto Verify page and setup
        self._goto_verify_page()
        self._selected_path = new_root
        self._set_tree_view_root(new_root)
        self.selected_project.setText(self._selected_path)

        if not skip_verification:
            # Start Verifying
            self._root_path = new_root
            message = "Verifying folder: {}".format(new_root)
            logger.info(message)
            self.statusbar.showMessage(message, STATUSBAR_MSG_DURATION)

            # schedule the scan verification process:
            self._start_checker_thread()

            logger.debug("Scheduled folder verification")

    def _get_path(self, path_or_file):
        """ Return path to path_or_file"""
        if os.path.isfile(path_or_file):
            # If it is a file, select the directory that contains it
            path_or_file = os.path.dirname(path_or_file)
        return path_or_file

    @staticmethod
    def get_manual(name):      
        path = os.path.normpath('./manual')
        path = os.path.join(path, name)
        return path

    def _set_tree_view_root(self, path):
        path = self._get_path(path)
        self._root_index = self.folder_tree.model().setRootPath(path)
        self.folder_tree.setRootIndex(self._root_index)

    def check_selected(self):
        """ pyQt slot Check here executed on tree
        """
        if len(self._selected_path) == 0:
            logger.warning("Cannot check selected path: Not initialized!")
            return

        logger.info("Checking selected folder '%s'", self._selected_path)

        self.open_root(False, self._selected_path)

        """
        self.current_root.setText(self._selected_path)
        self._root_index = self.folder_tree.model().setRootPath(self._selected_path)
        self.folder_tree.setRootIndex(self._root_index)

        self._root_path = self._selected_path
        self.statusbar.showMessage("Changed root folder to '{0}'".format(self._selected_path), STATUSBAR_MSG_DURATION)

        # schedule the scan verification process:
        self._start_checker_thread()
        """

    def _start_checker_thread(self):
        with self._working_lock:
            if self._working:
                logger.debug("Won't start the check worker thread because another job s running")
                return

            key_path = self._key_path
            if not is_valid_key(self._key_path):
                logger.info("Not a valid key file: '%s'", key_path)
                retval = show_message(self, "No valid RSA public key selected!",
                                      additional="Do you want to abort scanning and look for another key file?",
                                      yesno=True)

                if retval == QtWidgets.QMessageBox.Yes:
                    logger.debug("We should not start the working thread but and open another key file")
                    self.open_key_request.emit()
                    return
                else:
                    logger.debug("We should NOT open another key file but continue without it")

            self._n_scans_processed = 0
            self._set_working_status(True)
            self._working = True

            self._worker = VerifierThread(self._root_path, self._key_path)
            self._worker.setObjectName("VerifierThread")
            self._worker.scan_checked.connect(self.folder_checked)
            self._worker.finished.connect(self.all_folders_checked)
            self._worker.result_changed.connect(self.result_changed)
            self._worker.start()
            logger.info("Started verification thread on path '%s'", self._root_path)

    def all_folders_checked(self):
        """ pyQt slot
        """
        with self._working_lock:
            if not self._working:
                logger.warning("Finished a thread that should not be running!")
            else:
                self._working = False
                self._set_working_status(False)
                message = "Finished checking {0}".format(self._root_path)
                logger.info(message)
                self.show_statusbar_message(message)

                if self._is_scan_plan:
                    self.lineEdit_expectedHash.selectAll()
                    self.lineEdit_expectedHash.setFocus()

    def folder_checked(self, check_status: VerificationResult):
        """ pyQt slot
        """
        assert isinstance(check_status, VerificationResult)
        message = "Checked path {0}".format(check_status.scan_path)
        logger.info(message)
        self.show_statusbar_message(message)

        tree_contents = self.folder_tree.model()

        is_ole_file = os.path.isfile(self._root_path)  # That's enough to check for ole-file here.
        # Different root index for ScanPlanProjects or single scans
        if check_status.is_scanplan_project or (is_hashed_scan(self._root_path) and not is_ole_file):
            root = self._root_index.parent()
        else:
            root = self._root_index

        tree_updated = False
        for row in range(tree_contents.rowCount(root)):
            name_index = tree_contents.index(row, HDR_NAME, root)
            name = os.path.normpath(str(tree_contents.filePath(name_index)))
            if name == check_status.scan_path:
                status_index = tree_contents.index(row, HDR_STATUS, root)
                tree_contents.setData(status_index, check_status)
                tree_updated = True
                break  # there must be not more than one row matching the given path

        if not tree_updated:
            logger.warning("Found no entry in the displayed tree matching the path {}".format(check_status.scan_path))

        # Make sure, the tree view is updated.
        self.__set_root_path(self._root_path)

        if self._root_path == check_status.scan_path and check_status.is_swift_scan:
            show_message(self,
                         "The processed scan seems to belong to a Focus Swift sequence. "
                         + "No other scan of the sequence has been verified along with this one, "
                         + "so verification status will be set to FAILED.",
                         additional="Please navigate one folder up and verify the parent folder to "
                                    + "include all scans of the sequence.",
                         yesno=False)

        # Select Project only for ScanPlanProjects or single scans
        if check_status.is_scanplan_project \
                or (is_hashed_scan(self._root_path) and self._root_path == check_status.scan_path):
            logger.debug("Change displayed root folder to {}".format(check_status.scan_path))
            self.set_current_project(check_status)

    def result_changed(self, check_status: VerificationResult):
        assert not check_status.is_scanplan_project

        tree_contents = self.folder_tree.model()
        old_result: VerificationResult = tree_contents.get_verification_result(check_status.scan_path)
        old_result.hash_result = check_status.hash_result

        new_result: VerificationResult = tree_contents.get_verification_result(check_status.scan_path)

        self.__set_root_path(self._root_path)

        if not old_result.hash_result == new_result.hash_result:
            logger.error("Failed updating the status of the scan {}".format(check_status.scan_path))

    def open_key(self):
        """ pyQt slot
        """
        logger.info("Opening public key file")
        pem_filter = "Public RSA key files (*.pem)"
        key_path, file_type = QtWidgets.QFileDialog.getOpenFileName(self, caption="Open public key...",
                                                                    directory=self._key_path, filter=pem_filter)
        if len(key_path) == 0:
            logger.debug("User cancelled the key selection dialog")
            return

        key_path = os.path.normpath(key_path)
        logger.info("User selected key file: {0}".format(key_path))

        if not is_valid_key(key_path):
            logger.info("Not a valid key file: {0}".format(key_path))
            retval = show_message(self, "The selected file is not a valid RSA public key.",
                                  additional="Do you want to look for another key file?", yesno=True)

            if retval == QtWidgets.QMessageBox.Yes:
                logger.debug("We should open another key file")
                self.open_key_request.emit()
            else:
                logger.debug(
                    "Answer was not {0}. We should NOT open another key file".format(QtWidgets.QMessageBox.Yes))
            return

        self.key_details_action.setDisabled(False)
        self.show_statusbar_message("Public key file: '{0}'".format(key_path))
        self._key_path = key_path
        self._display_key_path()

    def check_root(self):
        """ pyQt slot
        """
        if self.is_verify:
            self.check_here_action.trigger()
        else:
            logger.info("Checking current root folder '%s'", self._root_path)

            # Refresh the Tree View
            self.folder_tree.model().setRootPath("")
            self._set_tree_view_root(self._root_path)

            self._start_checker_thread()
            self.show_statusbar_message("Processing scans in {0}".format(self._root_path))

    def set_result_badge(self, ok):
        if ok is True:
            self.result_badge.setStyleSheet(
                "border-image: url('images/verify_shield_green.svg') no-repeat center right fixed #ffffff;")
        elif ok is False:
            self.result_badge.setStyleSheet(
                "border-image: url('images/verify_shield_red.svg') no-repeat center right fixed #ffffff;")
        else:
            self.result_badge.setStyleSheet(
                "border-image: #ffffff;")

        # the folder_tree has to be updated, when the result changes. (otherwise it will only update on next mouse over)
        self.folder_tree.repaint()

    def set_current_project(self, result):
        if result is None:
            self.set_result_badge(None)
            self.current_verification_result = None
            self.verification_report.setEnabled(False)
            self.btn_show_report.setEnabled(False)
            self.selected_project.setText(self._selected_path)
            self.lineEdit_expectedHash_setText("")
            self.calculated_hash.setText("")
            self._set_scan_plan_project(False)
            self.calculated_hash_box.setVisible(False)
            return

        assert isinstance(result, VerificationResult)
        self.current_verification_result = result
        self._set_scan_plan_project(result.is_scanplan_project)

        self.verification_report.setEnabled(True)
        self.btn_show_report.setEnabled(True)
        self.selected_project.setText(result.scan_path)
        self.calculated_hash.setText(result.total_hash_calc)
        self.calculated_hash_box.setVisible(True)

        if result.is_scanplan_project:
            # Handle ScanPlan Project
            self.lineEdit_expectedHash_setText(result.expected_hash)
            if result.hash_result == HashResult.PASSED \
                    and result.sign_result == SignatureResult.PASSED \
                    and (result.expected_hash_result == HashResult.PASSED or
                         result.expected_hash_result == HashResult.NOT_CHECKED):
                self.set_result_badge(True)
            else:
                self.set_result_badge(False)

        else:
            # Handle Focus Scan
            if result.hash_result == HashResult.PASSED and result.sign_result == SignatureResult.PASSED:
                self.set_result_badge(True)
            else:
                self.set_result_badge(False)
            pass

    def check_is_verify(self, verify):
        self.is_verify = verify
        if self.is_verify:
            self.check_root_button.setText("VERIFY")
        else:
            self.check_root_button.setText("REVERIFY")

        self.check_root_button.setEnabled(False)

    def tree_cd_up(self):
        old_root_index = self._root_index
        old_path = self._root_path
        if os.path.isfile(self._root_path):
            # as _root_path may be an ole file, we need to go 2up in that case.
            old_path = os.path.dirname(self._root_path)
        head, tail = os.path.split(old_path)
        if head == old_path:
            head = ""
        self.__set_root_path(head)
        self._selected_path = ""

        self.check_is_verify(self._root_path == "" or self._root_path != self._selected_path)
        # Select old path
        if old_root_index is not None:
            self.folder_tree.expand(old_root_index)
            self.folder_tree.setCurrentIndex(old_root_index)
            # Re-Select the path, so the actions are up to date
            self.tree_selection_changed(old_root_index, None)

    def tree_selection_changed(self, selection, old_selection):
        self._selected_path = ""
        self.check_here_scanplan_action.setEnabled(False)
        self.check_here_action.setEnabled(False)

        # Find selected index
        index = None
        if isinstance(selection, QtCore.QItemSelection):
            if not selection.isEmpty():
                index = selection.indexes()[0]
        elif isinstance(selection, QtCore.QModelIndex):
            index = selection

        if index is None:
            return

        with self._working_lock:
            if self._working:
                logger.debug("Skipped the click on the tree because data is being processed now")
                self.set_current_project(None)
                return

        logger.debug("Processing a click on the path '%s'", self.folder_tree.model().filePath(index))
        content = self.folder_tree.model().data(index, FileSystemHashModel.HashDataRole)

        if content is None:
            # TODO: update the GUI with "Unknown" contents
            logger.debug("Unknown status")
            self._set_scan_plan_project(False)
            self.set_current_project(None)
        else:
            if isinstance(content, VerificationResult):
                self.set_current_project(content)

            else:
                # Get Project the file belong to
                result = self.folder_tree.model().get_verification_result_from_index(index)
                self.set_current_project(result)

        # Enable Actions
        selected_path = os.path.normpath(str(self.folder_tree.model().filePath(index)))
        is_dir = os.path.isdir(selected_path)

        # Set Verify/Reverify
        self.check_is_verify(self._root_path == "" or self._root_path != selected_path)

        if is_dir:
            if does_spl_exist(selected_path):
                self._selected_path = selected_path
                self.check_here_scanplan_action.setEnabled(True)
                self.check_here_action.setEnabled(False)
                if self.is_verify:
                    self.check_root_button.setEnabled(True)

            elif scan_count(selected_path, check_any=True) > 0:
                self._selected_path = selected_path
                self.check_here_scanplan_action.setEnabled(False)
                self.check_here_action.setEnabled(True)
                if self.is_verify:
                    self.check_root_button.setEnabled(True)

        if is_hashed_scan(selected_path):
            self._selected_path = selected_path
            self.check_here_scanplan_action.setEnabled(True)
            self.check_here_action.setEnabled(True)
            self.check_root_button.setEnabled(True)

    def btn_show_report_clicked(self):
        self.show_report()

    def show_report(self):
        """ pyQt slot
        """
        # create the report string
        with self._working_lock:
            if self._working:
                logger.debug("Skipped the request to create a report because data is being processed now")
                return

        if self.current_verification_result is None:
            logger.debug("No project selected")
            return

        if not isinstance(self.current_verification_result, VerificationResult):
            logger.debug("Not a scan")
            return

        assert isinstance(self.current_verification_result, VerificationResult)
        if self.current_verification_result == HashResult.HASH_LIST_MISSING:
            logger.debug("Not a scan, with a result object")
            return

        dialog = ReportDialog(self.current_verification_result, self)
        retval = dialog.exec_()
        logger.debug("Dialog has been closed with the return value %d", retval)

    def warn_invalid_key(self):
        """ pyQt slot
        """
        answer = show_message(self,
                              message="Invalid signature verification key",
                              icon=QtWidgets.QMessageBox.Warning,
                              additional=("No signature verification key loaded or the loaded"
                                          "key cannot be used for signature verification.\n"
                                          "Do you want to specify another key file?\n"),
                              yesno=True)

        if answer == QtWidgets.QMessageBox.Yes:
            logger.debug("We should load another key")
            self.open_key_request.emit()
        else:
            logger.debug("We should NOT load another key")

    def key_details(self):
        """ pyQt slot
        """
        logger.info("Displaying key details")
        key = load_rsakey(self._key_path)
        if key is None:
            logger.warning("Could not open the key file")
            QtCore.QTimer.singleShot(100, self.key_invalid.emit)
            return
        key_info = "{}\n".format(key.exportKey().decode('ASCII'))
        # key_info += "\nSize: {0}".format(key.size())   # not supported in Cryptodome
        key_info += "\nContains private key: {0}".format("YES" if key.has_private() else "NO")
        key_info += "\nCan encrypt: {0}".format("YES" if key.can_encrypt() else "NO")
        key_info += "\nCan sign: {0}".format("YES" if key.can_sign() else "NO")
        # key_info += "\nCan blind: {0}".format("YES" if key.can_blind() else "NO")  # not supported in Cryptodome

        show_message(self, "Signature verification RSA key", additional=key_info)

    def _accept_drag_event(self, e):
        try:
            if e.mimeData().hasUrls:
                for url in e.mimeData().urls():
                    folder = str(url.toLocalFile())
                    if does_spl_exist(folder):
                        self.statusbar.showMessage("Release to drop ScanPlan Project")
                    elif is_scan_verifyable(folder):
                        self.statusbar.showMessage("Release to drop folder with Focus Scans here")
                    else:
                        self.show_statusbar_message("Please drop a folder containing Focus Scans or a ScanPlan Project")
                        e.ignore()
                        continue

                    e.accept()
                    self.label_drag.setStyleSheet("border-image: url('images/create-new-folder-blue.svg');")
                    self.label_add_folders.setStyleSheet("color:  {};".format(self.COLOR_DROP))
                    self.label_subtext.setStyleSheet("color:  {};".format(self.COLOR_DROP))
                    for line in self.drop_lines:
                        line.setStyleSheet(line.styleSheet().replace("#acacac", self.COLOR_DROP))
                    for line in self.drop_lines_verify:
                        line.setStyleSheet(line.styleSheet().replace("#ffffff", self.COLOR_DROP))
                    return
        except:
            pass
        e.ignore()

    def dragEnterEvent(self, e):
        self._accept_drag_event(e)

    def dragLeaveEvent(self, e):
        self.statusbar.showMessage("")
        self.label_add_folders.setStyleSheet("color:  #acacac;")
        self.label_subtext.setStyleSheet("color:  #acacac;")
        self.label_drag.setStyleSheet("border-image: url('images/create-new-folder.svg');")
        for line in self.drop_lines:
            line.setStyleSheet(line.styleSheet().replace(self.COLOR_DROP, "#acacac"))
        for line in self.drop_lines_verify:
            line.setStyleSheet(line.styleSheet().replace(self.COLOR_DROP, "#ffffff"))
        e.accept()

    def dropEvent(self, e):
        self.dragLeaveEvent(e)
        if e.mimeData().hasUrls:
            e.setDropAction(QtCore.Qt.CopyAction)
            e.accept()

            for url in e.mimeData().urls():
                # Workaround for OSx dragging and dropping to be tested
                # Workaround for OSx dragging and dropping to be tested
                # if op_sys == 'Darwin':
                #    file_name = str(NSURL.URLWithString_(str(url.toString())).filePathURL().path())
                # else:
                file_name = str(url.toLocalFile())
                logger.debug("Dropped: '{}'".format(file_name))
                self.open_root(False, file_name)
                return
        else:
            e.ignore()

    def exit(self):
        logger.info("Exiting...")
        self._app.exit()
