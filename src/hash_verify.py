"""
Copyright (C) 2018 FARO Technologies Inc.
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License
version 3 or (at your option) any later version as published by the Free Software Foundation
and appearing in the file LICENSE included in the packaging of this file.

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This is the main file of the FARO scan hash and signature verification tool.
Here, the runtime is initialized and the main window is displayed.
"""
import argparse
import datetime
import logging
import os
import sys
import time

# To find QT5-DLLs in QT 5.13
if hasattr(sys, 'frozen'):
    os.environ['PATH'] = sys._MEIPASS + ";" + os.environ['PATH']

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import Qt
from appdirs import user_data_dir

from verify.verify import Verify
from version import __version__

LOG_FOLDER = os.path.join(user_data_dir("ScanVerificationTool", "FARO"), 'logs')

log_modules = ['verify', 'verification_algorithms', "report_dialog", "file_system_hash_model"]
logger = logging.getLogger(__name__)

if __name__ == '__main__':

    application_path = None
    if getattr(sys, 'frozen', False):
        # This is for mac bundle, should also work for windows version
        application_path = os.path.dirname(os.path.abspath(sys.executable))
        # Set certificates so SSL Verification of update server works
        os.environ['SSL_CERT_FILE'] = os.path.join(sys._MEIPASS, 'cert', 'cacert.pem')
    elif __file__:
        # When thy python file is running as interpreter
        application_path = os.path.dirname(os.path.abspath(__file__))
        application_path += "/.."

    # Change to correct dir to find all resources
    if application_path:
        os.chdir(application_path)

    # For Retina Display support
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)

    # Logging
    log_msg_format = '%(name)s | %(levelname)-7s (%(asctime)s.%(msecs)03d):  %(message)s'
    log_time_format = '%H:%M:%S'
    logging.basicConfig(level=logging.INFO, format=log_msg_format, datefmt=log_time_format)
    fmt = logging.Formatter(log_msg_format, datefmt=log_time_format)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)
    console_handler.setLevel(logging.DEBUG)

    # Ensure log folder exists
    if not os.path.exists(LOG_FOLDER):
        os.makedirs(LOG_FOLDER)

    log_filename = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d_%H-%M-%S.log')
    log_path = os.path.join(os.path.normpath(LOG_FOLDER), log_filename)

    print(log_path)

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.DEBUG)

    logger.setLevel(logging.INFO)

    for module in log_modules:
        log = logging.getLogger(module)
        log.propagate = False
        log.addHandler(console_handler)
        log.addHandler(file_handler)

    parser = argparse.ArgumentParser()
    parser.add_argument("--path",
                        help="Path to the project folder with the scans.")
    parser.add_argument("--debug", "-d",
                        help="Enable debug output into console", action='store_true')
    args = parser.parse_args()

    if args.debug:
        for module in log_modules:
            logging.getLogger(module).setLevel(logging.DEBUG)
    logger.debug("Args: {0}".format(args))

    # show the GUI
    app = QtWidgets.QApplication(sys.argv)

    # Application settings
    app.setOrganizationName("FARO")
    app.setOrganizationDomain("faro.com")
    app.setApplicationName("Scan Verification Tool")

    w = Verify(app, version=__version__)
    w.show()
    w.check_update()
    app.exec_()
