#!/usr/bin/python
import xml.etree.cElementTree as ET
import unittest

def getNVDTree(fileName):
    "Parse the given xml file into a tree and return the root of the tree"
    tree = ET.parse(fileName)
    root = tree.getroot()
    return root

def getNVDTreeFromYear(year):
    "Assume year is a number"
    fileName = "nvdcve-2.0-" + str(year) + ".xml"
    return getNVDTree(fileName)

def getCVEEntry(cve_id, root):
    "Given cve_id string and the root of the xml tree, search the xml tree for the node with the matching id and return the node with the matching attribute \
    Return nothing if element is not found"
    return root.find('.//*[@id="{}"]'.format(cve_id))


def checkRefType( cve, *keywords):
    "Given the subtree of the xml document with the cve entry as root, check the reference type against the given keywords. If there is a match, return true. \
    If not, return false"
    for keyword in keywords:
        elem = cve.find('.//*[@reference_type="{}"]'.format(keyword))
        if elem:
            return True
    return False

class XMLParseTests(unittest.TestCase):
    def setUp(self):
        self.nvdTree = getNVDTreeFromYear(2010)

    def testTree(self):
        self.assertTrue(self.nvdTree)

    def testGetCVEEntry(self):
        matchingCVEList = ['CVE-2010-0483','CVE-2010-0490','CVE-2010-0812']
        for cve in matchingCVEList:
            self.assertTrue(checkRefType(getCVEEntry(cve, self.nvdTree),"PATCH","VENDOR_ADVISORY"))
    

def main():
    unittest.main()

if __name__ == '__main__':
    main()


