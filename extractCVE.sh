#!/bin/sh

# Usage: ./extractCVE.sh <input1> <output>
# can have multiple input files
# last argument is always output file

for lastArg; do :; done # get the last argument of the command line
echo "Output to $lastArg"

if [ -f $lastArg ]; then
	rm -f $lastArg
fi

for file; do
	if [ "$file" == "$lastArg" ]; then
		break
	fi
	#filtered_lines=( $(grep "CVE" $file | cut -d ',' -f 1,3 | sed s/\'//g) )   
	echo "Reading $file"

	#grep -Po "CVE-\d{4}-\d{4}" $file | cut -d ',' -f 3 | sort -u
	CVE=( $(grep -Po "CVE-\d{4}-\d{4}" $file | cut -d ',' -f 3 | sort -u) ) > /dev/null


	if [ -z CVE ]; then
		echo "No CVE lines matched in $file"
		continue       
	fi

	for CVEID in "${CVE[@]}" 
	do
	#	echo $CVEID
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
		range=( $(tail -n +$startLine $xmlFileName | grep -n '</entry>' | cut -d ':' -f 1) )
		endLine=$((startLine+range-1))
	#	echo $startLine
	#	echo $endLine

		ARG1='VENDOR_ADVISORY'
		ARG2='PATCH'

		matchingLine=( $(sed -n -e "$startLine,$endLine s/$ARG1/&/p" -e "$startLine,$endLine s/$ARG2/&/p" $xmlFileName) )
	#	echo "$matchingLine"

		found='False'
		if [ ! -z "$matchingLine" ]; then
			found='True' # matching line is NOT empty, ergo a match was found
		fi

		echo "$CVEID,$found" >> "$lastArg"

	done

done

echo "Done!"
