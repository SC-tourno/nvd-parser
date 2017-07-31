#!usr/bin/python
import unittest
import csv
import sys
import getopt
import re
import readPatchInfo as rpi

def modifyCVSWithPatchInfo(cvsFile, csvOutFile, cveFile):
    "Reads in the CSV file containing the attack graph and modifies itby appending the CVE identifier of any rows containing such a vulnerability in one column and the availability of a patch in the second. \
    csvFile contains the unmodified attack graph \
    csvOutFile contains the file to be written to \
    cveFile contains the file which contains information about patch availability \
    "
    with open(cvsFile, 'r') as inFile, open(csvOutFile, 'w') as outFile:
        cvePatch = rpi.readInPatchInfo(cveFile)
        reader = csv.reader(inFile)
        writer = csv.writer(outFile)
        for row in reader:
            try:
                m = re.search('CVE-\d\d\d\d-\d\d\d\d',row[1])
                cve = m.group(0)
                row.append(cve)
                row.append(cvePatch[cve][0])
                row.append(cvePatch[cve][1])
                writer.writerow(row)
                print(row)
            except AttributeError:
                # No CVE identifier found on this line
                row.append("")
                row.append("")
                row.append("")
                writer.writerow(row)

class ModifyPatchTests(unittest.TestCase):

    def testFalse(self):
        self.assertFalse(False)

    def testModifyCVSWithPathcInfo(self):
        modifyCVSWithPatchInfo('VERTICES.CSV','MODIFIED_VERTICES.CSV','VERTICES_PATCH.CSV')
        self.assertTrue(True)


def main(argv):
    inputfile=''
    outputfile=''
    cvefile=''
    try:
        opts, args = getopt.getopt(argv,"i:o:c:",["input=","output=","cvefile="])
    except getopt.GetoptError:
        print ('usage:\nmodifyCVS.py -i <input> -o <output> -c <cvePatchInfo>\nOR\nmodifyCVS.py --input=<input> --output=<output> --cvefile=<cvefile>')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-i", "--input"):
            inputfile = arg
        elif opt in ("-o", "--output"):
            outputfile = arg
        elif opt in ("-c", "-cvefile"):
            cvefile = arg 

    modifyCVSWithPatchInfo(inputfile, outputfile, cvefile)

if __name__ == '__main__':
    main(sys.argv[1:])
