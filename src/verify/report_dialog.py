"""
Copyright (C) 2018 FARO Technologies Inc.
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License
version 3 or (at your option) any later version as published by the Free Software Foundation
and appearing in the file LICENSE included in the packaging of this file.

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This file defines the dialog showing the verification report of a scan.
"""

import subprocess
import logging
import platform
import os

from PyQt5 import QtGui, QtWidgets
from PyQt5.QtCore import Qt

from .functions import show_message
from .pdf_export import PdfExporter
from ui_gen.ui_report_dialog import Ui_ReportDialog


logger = logging.getLogger(__name__)


class ReportDialog(QtWidgets.QDialog, Ui_ReportDialog):
    """ Displays the detailed scan verification report.
    """

    def __init__(self, result, parent):
        QtWidgets.QDialog.__init__(self, parent=parent)
        self.setupUi(self)

        self.settings = parent.settings

        # Remove HelpButton
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        # Setup Signals and Slots
        self.pushButton_save.clicked.connect(self.save)
        self.pushButton_close.clicked.connect(self.close)
        self.pushButton_show.clicked.connect(self.show)

        # Setup properties
        self.saved_pdf = None
        self.result = result
        self.report = result.get_str(True)
        self.pushButton_show.setEnabled(False)

        # Insert text
        self.report_text.insertPlainText(self.report)

        # Scroll up
        self.report_text.moveCursor(QtGui.QTextCursor.Start)
        self.report_text.ensureCursorVisible()

    def show(self):
        """ pyQt slot
        """
        if self.saved_pdf:
            system = platform.system()
            if system == "Windows":
                subprocess.Popen(self.saved_pdf, shell=True)
            elif system == "Darwin":
                subprocess.Popen('/usr/bin/open "{}"'.format(self.saved_pdf), shell=True)
            elif system == "Linux":
                subprocess.Popen('xdg-open "{}"'.format(self.saved_pdf), shell=True)

    def save(self):
        """ pyQt slot
        """
        save_path = self.settings.value("report_path", "")
        head, tail = os.path.split(self.result.scan_path)
        directory = os.path.join(save_path, "ScanVerificationReport-{}.pdf".format(tail))

        save_filename, file_type = QtWidgets.QFileDialog.getSaveFileName(
            parent=self, caption='Report File', directory=directory, filter="PDF file (*.pdf);;"
                                                                            "Plain text file (*.txt)")

        if not save_filename:
            logger.debug("User cancelled file save dialog")
            return

        save_filename = os.path.normpath(save_filename)
        logger.debug("User selected file '%s' for saving the report", save_filename)

        filename, extension = os.path.splitext(save_filename)

        if os.path.exists(save_filename):
            logger.info("File '%s' already exists but user already confirmed overwriting")
        logger.info("Saving the report into the file '%s'", save_filename)

        try:
            if extension.lower() == '.txt':
                self.save_txt(save_filename)
            elif extension.lower() == '.pdf':
                self.save_pdf(save_filename)
            else:
                self.save_pdf(save_filename + '.pdf')
        except PermissionError:
            show_message(self, "No permission to write the file: '{}'\n\n"
                               "Check if the file is opened in an other program.\n"
                               "Check if you have permission to write to that folder.".format(save_filename),
                         icon=QtWidgets.QMessageBox.Warning)

        self.settings.setValue("report_path", os.path.dirname(save_filename))

    def save_txt(self, save_filename):
        with open(save_filename, 'w') as f:
            f.write(self.report)

    def save_pdf(self, save_filename):
        export = PdfExporter()
        if export.make_pdf(self.report, save_filename):
            self.saved_pdf = save_filename
            self.pushButton_show.setEnabled(True)
