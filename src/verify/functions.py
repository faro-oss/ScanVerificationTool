"""
Copyright (C) 2018 FARO Technologies Inc.
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License
version 3 or (at your option) any later version as published by the Free Software Foundation
and appearing in the file LICENSE included in the packaging of this file.

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

Here, some utility functions are defined.
"""

import os
import logging

from PyQt5 import QtWidgets, QtCore

IMG_FOLDER = 'images'
logger = logging.getLogger(__name__)


def does_spl_exist(path):
    try:
        for item in os.listdir(path):
            if item.endswith(".spl"):
                return True
        return False
    except:
        return False


def get_icon_path(icon):
    return os.path.join(IMG_FOLDER, icon)


def show_message(parent, message="", icon=QtWidgets.QMessageBox.Information, additional="", yesno=False):
    """ Helper function for displaying popup messages
        Placed outside any class for the possibility of being used by any parent
        :rtype: int
        :return: One of the enum values Yes, 'No or Ok as defined in QtGui.QMessageBox
    """
    logger.info("Showing a %s message box: Message(s): '%s'\n%s",
                ('modal' if yesno else 'information'),
                message, additional)
    msg = QtWidgets.QMessageBox(parent)
    msg.setWindowTitle("FARO Scan Verification Tool")
    msg.setTextFormat(QtCore.Qt.RichText)
    msg.setText(message)
    msg.setIcon(icon)

    # Win MessageBox Width
    horizontal_spacer = QtWidgets.QSpacerItem(400, 0, QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Expanding)
    layout = msg.layout()
    layout.addItem(horizontal_spacer, layout.rowCount(), 0, 1, layout.columnCount())

    if len(additional) > 0:
        msg.setInformativeText(additional)

    if yesno:
        msg.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
    else:
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok)

    retval = msg.exec_()
    logger.debug("Message box: user pressed {0}".format(retval))
    return retval
