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

Install [Miniconda](https://docs.conda.io/en/latest/miniconda.html).  
All dependencies are listed in `environment.yml` and can be installed via conda.

---

## How to get started
Since this is a GPL Project, you can use [PyCharm Community Edition](https://www.jetbrains.com/pycharm/download) to develop.  
You can [create a Conda Virtual Environment](https://www.jetbrains.com/help/pycharm-edu/conda-support-creating-conda-virtual-environment.html) in PyCharm; the name will default to the project directory name.  
Then, you can update the virtual environment to this project's requirements based on `environment.yml`:
  ```
  conda env update -f environment.yml
  ```

You can also directly use conda to create a virtual environment for the development.  
The `conda env...` command above will automatically create the environment `svt` and install all the dependencies into it.

In the following, we'll assume, that the environment name is `svt`.

### Compile the Qt5 dialogue files
Windows:
```
conda run -n svt python -m PyQt5.uic.pyuic -x src/ui/report_dialog.ui -o src/ui_gen/ui_report_dialog.py
conda run -n svt python -m PyQt5.uic.pyuic -x src/ui/hash_verify.ui -o src/ui_gen/ui_layout.py
```

MacOS:
```
conda run -n svt python -m PyQt5.uic.pyuic -x src/ui/hash_verify.mac.ui -o src/ui_gen/ui_layout.py
conda run -n svt python -m PyQt5.uic.pyuic -x src/ui/report_dialog.mac.ui -o src/ui_gen/ui_report_dialog.py
```

### Run the code
```
conda run -n svt python src/hash_verify.py
```
