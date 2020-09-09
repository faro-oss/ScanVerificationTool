'''
Copyright (C) 2018 FARO Technologies Inc. 
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License 
version 3 or (at your option) any later version as published by the Free Software Foundation 
and appearing in the file LICENSE included in the packaging of this file.  

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This script creates an executable for the scan hash and signature verification tool.
Along with the EXE, the folders required for the operation are initialized. 
Also, resources and used libraries are copied into the output folder.
'''

from distutils.core import setup
import os, sys

# 
from verify.hash_verify import KEY_PATH, KEY_FOLDER, LOG_FOLDER, IMG_FOLDER

from glob import glob

print("Setup.py is outdated.")
exit(-1)

SRC_FOLDER = 'src'
SRC_FILES = ['hash_verify.py', 'verification_algorithms.py', 'setup.py', 'hash_verify.ui', 'report_dialog.ui', 'version.py']
SRC_FILES.extend([(app+'LICENSE') for app in ['', 'Qt_', 'PyQt4_', 'pycrypto_', 'olefile_', 'BlueSphere_icons_']])

data_files = [('Microsoft.VC90.CRT', glob(r'..\..\..\dist\Microsoft.VC90.CRT_x64\*.*')), 
              (IMG_FOLDER, glob(r'images\*.svg')),
              (IMG_FOLDER, [os.path.join(IMG_FOLDER, '*.png')]),
              (KEY_FOLDER, [KEY_PATH]),
              (LOG_FOLDER, []),
              (SRC_FOLDER, SRC_FILES),
              (os.path.join(SRC_FOLDER, IMG_FOLDER), glob(r'images\*.svg')),
              (os.path.join(SRC_FOLDER, IMG_FOLDER), [os.path.join(IMG_FOLDER, '*.png')]),
              (os.path.join(SRC_FOLDER, KEY_FOLDER), [KEY_PATH])
              ]

print("\n".join([str(item) for item in data_files]))

sys.argv.append('py2exe')


p2exe_opts = {'includes': ['argparse', 'sip']}

setup(data_files=data_files, 
      windows=[{'script': 'hash_verify.py',
                "icon_resources": [(0, os.path.join(IMG_FOLDER, 'verify.ico'))],
                'dest_base': "FSVT"
                }],
      options={'py2exe': p2exe_opts},
      zipfile=None)
