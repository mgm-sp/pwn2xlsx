#!/usr/bin/python3
# encoding: utf-8
# Transform Nmap xml to Excel
# Author: Benjamin Kellermann; Jan Rude
# License: GPLv3
import xml.etree.ElementTree as ET
from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo
import sys
import os

if len(sys.argv) < 3:
    sys.exit("Usage: %s scan1.xml [scan2.xml [scan...]] outfile.xlsx" % sys.argv[0])

target = sys.argv.pop()

if os.path.exists(target):
    sys.exit('ERROR: Output %s already exists' % target)

ports = []
for f in sys.argv[1:]:
    xml = ET.parse(f)
    root = xml.getroot()

    for host in root.iter('host'):
        address = host.find('address').get('addr')
        hostname = []
        if host.find('hostnames') is not None:
            for h in host.find('hostnames').iter('hostname'):
                hostname.append(h.get('name'))
        if host.find('ports') is not None:
            for p in host.find('ports').iter('port'):
                port = str(p.get('portid')) + "/" + p.get('protocol')
                reason = p.find('state').get('reason')
                product = []
                if p.find('service') is not None:
                    service = p.find('service').get('name')
                    product.append(p.find('service').get('product'))
                    product.append(p.find('service').get('version'))
                    product.append(p.find('service').get('extra'))
                    product = [x for x in product if x is not None]
                else:
                    service = ""
                ports.append([address, ", ".join(hostname), port, reason, service, " ".join(product)])

# Save the file
# Open up a new excel file
wb = Workbook()

ws = wb.worksheets[0]
ws.title = "Services"
ws.append(["Adresse", "Hostname", "Port", "Erkennung", "Service", "Produkt"])
ws.column_dimensions['A'].width = 12
ws.column_dimensions['B'].width = 50
ws.column_dimensions['C'].width = 10
ws.column_dimensions['D'].width = 15
ws.column_dimensions['E'].width = 20
ws.column_dimensions['F'].width = 50

# Add a default style with striped rows and banded columns
style = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True, showColumnStripes=False)

for entry in ports:
    ws.append(entry)

# Get Table dimensions
if ws.max_row == 1:  # if table is empty
    dim = "A1:J2"
else:
    dim = ws.dimensions

tab = Table(displayName="Services", ref=dim)
tab.tableStyleInfo = style
ws.add_table(tab)
wb.save(target)
