#!/usr/bin/python
import unittest
import csv
import sys
import re
import findPatch as FP    # Make sure findPatch.py is in same directory
import getopt

def readGraph(f):
    "Reads the CSV file and converts it to a list. Each row is itself a list. \
    Returns CSV file as a list (of lists)"
    attGraph = csv.reader(f)
    attGraphList = list(attGraph)
    return attGraphList

def searchForCVE(attGraphList):
    "Finds all the lines within the CSV files which contain a CVE identifier. \
    Returns all lines as list"
    CVERows = []
    for row in attGraphList:
        if "CVE" in row[1]:
            CVERows.append(row)
    
    return CVERows

def extractCVEFromRow(rowList):
    "Extracts the CVE identifier substring from each row. \
    Returns list of CVE identifiers."
    cveList = []
    for row in rowList:
        try:
            m = re.search('CVE-\d\d\d\d-\d\d\d\d',row[1])
            cve = CVE(m.group(0),row[0])
            cveList.append(cve)
        except AttributeError:
            print("%s row does not have CVE identifier".format(row))
    return cveList

def searchForPatch(cve, nvdTree):
    "Searches tree using CVE identifiers. Sets patchExists boolean value if keyword has been found "
    cve.setPatchExists((FP.checkRefType(FP.getCVEEntry(cve.getIDStr(), nvdTree),"PATCH","VENDOR_ADVISORY")))

def writeOutputToFile(CVEList, csvList, newFile):
    "Writes an extra two columns to the original csv file. \
            First extra column writes the CVE identifier \
            Second extra column write True/False depending on whether a patch was found or not"
    outf = open(newFile, 'w', newline='')
    outputWriter = csv.writer(outf)
    i = 1
    for row in csvList:
        newCells = ["",""]
        for cve in CVEList:
            if i == cve.getRow():
                newCells = ["{}".format(cve.getIDStr()),"{}".format(cve.getPatchExists())]
                break
        row.extend(newCells)
        outputWriter.writerow(row)
        i += 1
    outf.close()

class CVE:
    # Could be useful for future use cases when storing CVE information as one long string becomes cumbersome
    def __init__(self, cveStr, row):
        self.year = int(cveStr[4:8])
        self.ID = (cveStr[9:13])
        self.row = int(row)
        self.patchExists = False

    def setPatchExists(self,bool_val):
        self.patchExists = bool_val

    def getRow(self):
        return self.row

    def getYear(self):
        return self.year

    def getPatchExists(self):
        return self.patchExists

    def getIDStr(self):
        return "CVE-" + str(self.year) + "-" + (self.ID)

class CSVTests(unittest.TestCase):
    def setUp(self):
            self.csvFile = open('VERTICES.CSV')
            self.gr = readGraph(self.csvFile)
            self.nvdTree = FP.getNVDTreeFromYear(2010)

    def tearDown(self):
        self.csvFile.close()


    def testFalse(self):
        self.assertFalse(False)
    
    def testReadGraph2(self):
            self.assertTrue(any(self.gr)) # If list is empty, return false

    def testSearchForCVE(self):
            matchingList = searchForCVE(self.gr)
            numRows = 3
            self.assertTrue(len(matchingList)==numRows)

    def testExtractCVEFromRow(self):
        matchingList = searchForCVE(self.gr)
        CVEList = extractCVEFromRow(matchingList)
        matchingCVEStrList = ["CVE-2010-0483","CVE-2010-0490","CVE-2010-0812"]
        rowList = ["27","40","59"]
        matchingCVEList = []
        for CVEStr, rowStr in zip(matchingCVEStrList, rowList):
            matchingCVEList.append(CVE(CVEStr,rowStr))

        for cve1,cve2 in zip(CVEList, matchingCVEList):
            self.assertTrue(cve1.getIDStr() == cve2.getIDStr())
            self.assertTrue(cve1.row == cve2.row)

    def testWriteOutputToFile(self):
        matchingList = searchForCVE(self.gr)
        CVEList = extractCVEFromRow(matchingList)
        searchForPatch(CVEList, self.nvdTree)
        print(CVEList)
        writeOutputToFile(CVEList, self.gr, "NEW_VERTICES.csv")
        

"""
    def testSearchForPatch(self):
        matchingList = searchForCVE(self.gr)
        CVEList = extractCVEFromRow(matchingList)
        searchForPatch(CVEList, self.nvdTree)
        for cve in CVEList:
            self.assertTrue(cve.patchExists)
"""

"""
    def testSearchCVEForPatch(self):
        matchingList = searchForCVE(self.gr)
        CVEList = extractCVEFromRow(matchingList)
        for cve in CVEList:
            self.assertTrue(FP.checkRefType(FP.getCVEEntry(cve.getIDStr(),self.nvdTree),"PATCH","VENDOR_ADVISORY"))
"""


def main(argv):
    #unittest.main()
    inputfilename = ''
    outputfilename = ''
    try:
        opts, args = getopt.getopt(argv,"dhi:o:",["debug","help","ifilename=","ofilename="])
    except getopt.GetoptError:
        print ('getVulnerabilities.py -i <inputfilename> -o <outputfilename>')
        sys.exit(2)
        
    for opt, arg in opts:
        if opt in ("-d","--debug"):
            global _debug
            _debug = 1
        if opt in ('-h',"--help"):
            print ('getVulnerabilities.py -i <inputfilename> -o <outputfilename>')
            print ('Make sure you have all the appropriate nvd xml filenames beforehand')
            sys.exit()
        elif opt in ("-i", "--ifilename"):
            inputfilename = arg
        elif opt in ("-o", "--ofilename"):
            outputfilename = arg
    print ('Input filename is {}'.format( inputfilename))
    print ('Output filename is {}'.format(outputfilename))

    with open(inputfilename, 'r') as infile, open(outputfilename, 'w') as outfile:
        csvList = readGraph(infile)
        CVERowList = searchForCVE(csvList)
        CVEList = extractCVEFromRow(CVERowList)
        yearSet = set()
        for CVE in CVEList:
            yearSet.add(CVE.getYear()) # Ensure no duplicates
        nvdXMLFiles = dict()
        for year in yearSet:
            nvdXMLFiles[year] = FP.getNVDTreeFromYear(year)  # Read in the appropriate xml files given the set of years
        for CVE in CVEList:
            searchForPatch(CVE, nvdXMLFiles[CVE.getYear()])
            print("{}: {}".format(CVE.getIDStr(), CVE.getPatchExists()))
        writeOutputToFile(CVEList, csvList, outputfilename)
        
    

if __name__ == '__main__':
    main(sys.argv[1:])
