#!/bin/sh

# Assume $1 is input csv file
# $2 is output file
# Check if xml files are present. If not wget them from nvd website
filtered_lines=( $(grep "CVE" $1 | cut -d ',' -f 1,3 | sed s/\'//g) )   
CVE=( $(grep "CVE" $1 | cut -d ',' -f 3 | sed s/\'//g | sort -u) ) > /dev/null

for CVEID in "${CVE[@]}"
do
#	echo $CVEID
	year=( $(echo $CVEID |cut -d '-' -f 2 ) )
#	echo $year
	xmlFileName="nvdcve-2.0-$year.xml"
	if [ ! -f $xmlFileName ]; then
		echo "You don't have $xmlFileName!"
		echo "Let me retrieve that for you..."
		wget -q "https://static.nvd.nist.gov/feeds/xml/cve/2.0/$xmlFileName.zip"
		unzip -q "$xmlFileName.zip" && rm -f "$xmlFileName.zip"
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

	echo "$CVEID,$found" >> "$2"

done


