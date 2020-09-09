## Introduction
This repository contains the source code of the FARO Scan Verification Tool that 
allows to verify the digital scan signature created by the scanner and thus check
whether the scan data has been manipulated since the scanner finalized the scan.

The tool is released open source. The latest released version can be downloaded 
from the [FARO 3D App Center](https://3d-apps.faro-europe.com/product/faro-scan-verification-tool/)

---

## License

The Scan Verification Tool is distributed under the GNU General Public License (GPL) version3. You can view the license terms in the file [LICENSE](LICENSE). 

The license terms of used third-party components are available in the subrirectory [licenses](licenses).

---

## Prerequisites

Install [Miniconda](https://docs.conda.io/en/latest/miniconda.html)<br>
All dependencies are in environment.yml and can be installed via conda.

---

## How to get started
You should use conda to create a virtual environment for development.<br>
As this is a GPL Project, you can use [PyCharm Community Edition](https://www.jetbrains.com/pycharm/download) to develop.<br>
In PyCharm, [create a Conda Virtual Environment](https://www.jetbrains.com/help/pycharm-edu/conda-support-creating-conda-virtual-environment.html)
; the name will default to the project directory name.
Now, update the virtual environment, based on environment.yml.
`$ conda env update environment.yml`<br>

Also, the Scrips in build_scripts have to be started from the project root folder.

Assuming, the environment name is svt

##### Compile the Qt5 dialogue files
`$ conda run python -m PyQt5.uic.pyuic -x src/report_dialog.ui -o src/ui_report_dialog.py`<br>
`$ conda run python -m PyQt5.uic.pyuic -x src/hash_verify.ui -o src/ui_layout.py`

##### Run the code
`$ conda run src/hash_verify.py`
