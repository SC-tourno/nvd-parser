#!/bin/bash

# Usage: ./extractCVE.sh <input1 [input2 ...]>  
# can have multiple input files
# last argument is always output file

#if [ -z $2 ]; then
#	output=$1.out
#else
#	for output; do :; done # get the last argument of the command line. Last argument = output
#fi
if [ -z $1 ]; then
	echo "Usage: ./extractCVE.sh <input1 [input2 ...]>"
fi

echo "Type the name of the output file [default: PATCH_$1]:"
read output
if [ -z $output ]; then
	output="PATCH_$1"
fi

echo "Output to $output"

if [ -f $output ]; then
	rm -f $output
fi

for file; do
	if [ "$file" == "$output" ]; then
		break
	fi
	echo "Reading $file"

	CVE=( $(grep -Po "CVE-\d{4}-\d{4}" $file | cut -d ',' -f 3 | sort -u) ) > /dev/null


	if [ -z CVE ]; then
		echo "No CVE lines matched in $file"
		continue       
	fi

	for CVEID in "${CVE[@]}" 
	do
		echo $CVEID
		year=( $(echo $CVEID |cut -d '-' -f 2 ) )
	#	echo $year
		xmlFileName="nvdcve-2.0-$year.xml"
		if [ ! -f $xmlFileName ]; then
			echo "You don't have $xmlFileName!"
			echo "Let me retrieve that for you..."
			wget  -q --show-progress "https://static.nvd.nist.gov/feeds/xml/cve/2.0/$xmlFileName.zip"
			unzip -q "$xmlFileName.zip" && rm -f "$xmlFileName.zip"
			if [ ! -f $xmlFileName ]; then
				# if file still does not exist, skip
				continue
			fi
		fi
		startLine=( $(grep -n "$CVEID" $xmlFileName | cut -d ':' -f 1) )
		if [ -z startLine ]; then
			echo "$CVEID was not found!"
			continue
		fi
		
		range=( $(tail -n +$startLine $xmlFileName | grep -n '</entry>' | cut -d ':' -f 1) )
		endLine=$((startLine+range-1))

#		Not every vulnerability has a patch (e.g. CVE-2004-2761) Best to err on the safe side and only output true if link with "PATCH" exists
#		ARG1='VENDOR_ADVISORY'
		ARG2='PATCH'

#		matchingLine=( $(sed -n -e "$startLine,$endLine s/$ARG1/&/p" -e "$startLine,$endLine s/$ARG2/&/p" $xmlFileName) )
		matchingLine=( $(sed -n -e "$startLine,$endLine s/$ARG2/&/p" $xmlFileName) )

		found='False'
		if [ ! -z "$matchingLine" ]; then
			found='True' # matching line is NOT empty, ergo a match was found
		fi

		echo "$CVEID,$found" >> "$output"

	done

done

echo "Done!"
