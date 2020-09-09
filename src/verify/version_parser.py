"""
Copyright (C) 2018 FARO Technologies Inc. 
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License 
version 3 or (at your option) any later version as published by the Free Software Foundation 
and appearing in the file LICENSE included in the packaging of this file.  

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This file defines a class for comparing software versions between each other.
"""

class Version:
    def __init__(self, version_str):
        self.version = tuple(map(int, (version_str.split("."))))

    def __repr__(self):
        ret = ""
        for item in list(self.version):
            ret += str(item) + "."
        return ret.rstrip(".")

    def __eq__(self, value):
        return self.version == value

    def __gt__(self, value):
        return self.version > value

    def __lt__(self, value):
        return self.version < value