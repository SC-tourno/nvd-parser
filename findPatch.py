#!/usr/bin/python
import unittest
import os
import re
import argparse
import subprocess

def get_cves(dirName):
    " Returns a dictionary of cves where the key is the ID and the value is the CVE object "
    cveDict = dict()
    for fileName in os.listdir(dirName):
        filePath=os.path.join(dirName,fileName)
        with open(filePath, 'r') as cveEntryFile:
            vulnProds = get_vuln_products(cveEntryFile)
            refList = get_refs(cveEntryFile)
            cveDict[fileName] = CVEEntry(fileName, vulnProds, refList)
    return cveDict

def get_vuln_products(cveEntryFile):
    " Returns a list of VulnerableProduct objects"
    vulnProductList = list()
    vulnProductMatch = re.compile(r"<vuln:product>cpe:\/([ao]):(\w+):(\w+):*:(\w+)</vuln:product")
    breakLine = re.compile(r'<\/vuln:vulnerable-software-list>')
    for line in cveEntryFile:
        m = vulnProductMatch.search(line)
        if m:
            vType   =   (m.group(1))
            vendor  =   (m.group(2))
            prod    =   (m.group(3))
            ver     =   (m.group(4))
            vulnProd = VulnerableProduct(vType,vendor,prod,ver)
            vulnProductList.append(vulnProd)
        if breakLine.search(line):
            return vulnProductList

def get_refs(cveEntryFile):
    "Returns a list of Reference objects"
    refList = list()
    vulnRefsMatch = re.compile(r"<vuln:references.*reference_type=\"(.*)\">\n.*", re.MULTILINE)
    vulnSrcMatch = re.compile(r"<vuln:source>(.*)</vuln:source>")
    vulnURLMatch = re.compile(r"<vuln:reference href=\"(.*)\" xml")
    breakLine = re.compile(r'<vuln:scanner>')
    vulnRefs=""
    vulnSrc=""
    vulnURL=""
    for line in cveEntryFile:
        m = vulnRefsMatch.search(line)
        if m:
            vulnRefs = m.group(1)
            continue
        n = vulnSrcMatch.search(line)
        if n:
            vulnSrc = n.group(1)
            continue
        p = vulnURLMatch.search(line)
        if p:
            vulnURL = p.group(1)
            refList.append(Reference(vulnURL,vulnRefs,vulnSrc))
        if breakLine.search(line):
            return refList


class CVEEntry:
    def __init__(self, cveId, vulnProducts, refs):
        self.id = cveId
        self.vulnProducts = vulnProducts
        self.refs = refs

class VulnerableProduct:
    def __init__(self, product_type, vendor, product, ver):
        self.product_type = product_type
        self.vendor = vendor
        self.product = product
        self.ver = ver
        self.patch = False
        self.restart = False

    def toggle_patch_exists(value):
        self.patch = value

    def toggle_restart_required(value):
        self.restart = value

class Reference:
    def __init__(self, link, refType="", src=""):
        self.link = link
        self.refType = refType
        self.src = src

class ParseTests(unittest.TestCase):
    def setUp(self):
        self.scriptDir = os.path.dirname(os.path.abspath(__file__))
        self.dirName='cve_entries'
        self.cveDict = get_cves(self.dirName)

    def test_dir(self):
        print(self.scriptDir)
        self.assertTrue(self.scriptDir)

    def test_get_cve(self):
        self.cveEntries = ['CVE-2004-2761','CVE-2005-1794','CVE-2010-0483','CVE-2010-0490','CVE-2010-0812']
        self.assertTrue(set(self.cveEntries) == set(self.cveDict.keys()))

    def test_search_microsoft_bulletin(self):
        dirName = "data"
        msBulletinFileName = "BulletinSearch.csv" 
        msBulletinFilePath = os.path.join(self.scriptDir,dirName,msBulletinFileName)
        self.assertTrue(msBulletinFilePath == "/home/sc/python/crism_nvd/data/BulletinSearch.csv")
        for cveEntry in self.cveDict.values():
            if (vulnProd.vendor == "microsoft"):
                    search_microsoft_bulletin(cveEntry.Id, vulnProd, msBulletinFilePath)


def main():
    unittest.main()

if __name__ == '__main__':
    main()


