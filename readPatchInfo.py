#!/usr/bin/python
import sys
import csv
import unittest

def readInPatchInfo(inputFile):
    "Reads in the CSV file containing CVE identifier in the first column and boolean value indicating patch availability in the second column, and boolean value indicating a restart is necessary in the third column. \
    Returns dictionary that contains the CVE identifier as the key and the path availability boolean value as the dictionary value. \
    "
    CVEPatchdic = dict()
    with open(inputFile, 'r') as inFile:
        reader = csv.reader(inFile)
        for row in reader:
#            patchRestart = (row[1] == 'True', row[2] == 'True')  
            patchRestart = (row[1], row[2])  
            print(patchRestart)
            CVEPatchdic[row[0]] = patchRestart
    return CVEPatchdic    

class PatchInfoReaderTests(unittest.TestCase):

    def testFalse(self):
        self.assertFalse(False)

    def testDictionaryEquivalency(self):
        dic1 = {
            'a':True,
            'b':False
            }
        dic2 = {
            'a':True,
            'b':False
            }
        self.assertTrue(dic1 == dic2)

    def testReadInPatchInfo(self):
        actualCVEDic = {
            "CVE-2010-0483": True,
            "CVE-2010-0490": True,
            "CVE-2010-0812": True,
            "CVE-2004-2761": True,
            "CVE-2005-1794": True
            }                
        CVEdic = readInPatchInfo('VERTICES_PATCH.CSV')        
        self.assertTrue(CVEdic == actualCVEDic)
        
def main():
    unittest.main()
    
if __name__ == '__main__':
    main()
