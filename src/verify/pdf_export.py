"""
Copyright (C) 2018 FARO Technologies Inc.
This file is part of the "FARO Scan Verification Tool".

This file may be used under the terms of the GNU General Public License
version 3 or (at your option) any later version as published by the Free Software Foundation
and appearing in the file LICENSE included in the packaging of this file.

This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

This file defines the functionality of exporting of verification results for a scan
into a PDF report.
"""

import fpdf
import os
import time


class PdfExporter:

    def __init__(self):
        """
        Create a PDF
        """
        self.pdf = None
        self.max_lines = 60  # for A4
        self.page_start = 40 # Where to start the page
        self.start_1st = 0   # First line on 1st page
        self.start_2nd = 3   # First line on 2nd and above pages
        self.product_name = "Scan Verification Tool"

        self.level = ["PASSED", "PASSED", "FAILED", "FAILED", "FAILED"]

        self.colors = {'black': (0, 0, 0),
                       'red': (180, 0, 0),
                       'yellow': (250, 200, 0),
                       'green': (0, 180, 0),
                       'gray': (150, 150, 150)}

    def make_pdf(self, report, file_name, format='a4'):
        self.pdf = fpdf.FPDF(format=format)

        if format == 'letter':
            self.max_lines = 55

        date_str = time.strftime("%Y-%m-%d")
        time_str = time.strftime("%H:%M:%S")

        self.add_metadata()

        lines = str(report).rstrip('\n').splitlines()

        i = self.start_1st
        page = 1
        pages = self.calc_pages(len(lines))
        self.create_page(page, pages)

        for line in lines:
            if i > self.max_lines:
                page += 1
                self.create_page(page, pages)
                i = self.start_2nd
            if line.startswith("**"):
                self.pdf.set_text_color(*self.colors['gray'])
            else:
                self.pdf.set_text_color(*self.colors['black'])
            self.pdf.text(x=15, y=self.page_start + (i*4), txt=line)
            i += 1

        self.pdf.output(file_name, "F")
        return True

    def calc_pages(self, length):
        left = length
        p = 1
        left -= self.max_lines + self.start_1st
        while left > 0:
            p += 1
            left -= self.max_lines + self.start_2nd
        return p

    def add_metadata(self):
        self.pdf.set_creator("FARO {} PDF Creator".format(self.product_name))
        self.pdf.set_author("FARO {}".format(self.product_name))
        self.pdf.set_subject("{} Report".format(self.product_name))
        self.pdf.set_font('Courier', 'B', 10)

    def create_page(self, page, pages):
        self.pdf.add_page()
        self.print_header()
        self.print_footer(page, pages)

    def print_header(self):
        """ Adds a header bar with the logos to the report page.
        """
        img_path = self.get_image("FARO_logo_Blue_clipped.png")
        self.pdf.image(img_path, x=15, y=17, w=48, h=0, type='png', link='')

        img_path = self.get_image("verify_trans.png")
        self.pdf.image(img_path, x=175, y=15, w=20, h=0, type='png', link='')

        self.pdf.set_text_color(*self.colors['black'])
        self.pdf.text(x=15, y=15, txt="Scan Verification Tool")

    def print_footer(self, page, pages):
        self.pdf.set_text_color(*self.colors['black'])
        self.pdf.text(x=15, y=self.page_start + 4 * (self.max_lines + 2), txt="Page {} of {}".format(page, pages))

    @staticmethod
    def get_image(image):
        path = os.path.join(os.getcwd(), "images")
        path = os.path.join(path, image)
        return path
