#!/bin/bash
# Usage: ./extractCVE.sh <input1 [input2 ...]>  
# can have multiple input files
# This script is not meant to provide the final assessment on whether a patch exists and whether a restart is required.
# Instead, it's only meant to extract the vulnerabilities from the input attack graphs, and find their respective entries in the NVD database.
# From there, this script will write relevant information about each vulnerability to a respective file for further processing

search_for_vuln_products () {
	# Dump all fields in <vuln:product> tags
	# /o means (I presume) OS
	# /a means (I presume) application
	__startLine=$1
	__endLine=$2
	sed -n -e "${__startLine},${__endLine}p" $xmlFileName | grep '<vuln:product>' | cut -d ':'  -f 3-8 | cut -d "/" -f 2 
	#| sed -e 's/</;/' -e 's/\n//' > 
}

search_for_vuln_vendors () {
	__startLine=$1
	__endLine=$2
	__vuln_list=
	__vuln_list=$( search_for_vuln_products $1 $2 )
	echo "$__vuln_list" 
}

search_for_microsoft_vuln (){
	__startLine=$1
	__endLine=$2
	__contains_microsoft=$(search_for_vuln_vendors $startLine $endLine | grep "microsoft") 
	if [ ! -z "$__contains_microsoft" ]; then
		# cve affects microsoft product
		# look through MS database
#		echo "$__contains_microsoft"		
		__Bulletin="BulletinSearch.csv"
#		echo "Searching for $CVEID"
#		grep "$CVEID" $__Bulletin
#__restart=( $(awk -v pat="$CVEID" -F, 'pat{print NR-1}' $__Bulletin) ) { print $((NF-1))}' $__Bulletin) )
		__restart=$(grep  "$CVEID" $__Bulletin | grep -o -m 1 "Yes\|Maybe\|No")
#		if [[  "$__restart" == "Yes" ]]; then
#			__restart="True"
#		eli
#			__restart="?"
#		fi
		echo "$__restart"
	fi
}

list_urls (){
#	Output list of urls
	__startLine=$1
	__endLine=$2
	sed -n -e "${__startLine},${__endLine}p" $xmlFileName | grep -A 2 '<vuln:reference'  > $CVEID_url_list
}

search_for_patch_url () {
#	ARG1='VENDOR_ADVISORY'
	__startLine=$1
	__endLine=$2
	ARG2='PATCH'
	__matchingurl=( $(sed -n -e "${startLine},${endLine}p" $xmlFileName | grep -P -A 2 "reference_type=\"$ARG2\"") )
	echo $__matchingurl
}

#-------------------------------------------------
# BEGIN EXECUTION
#-------------------------------------------------
if [ -z $1 ]; then
	echo "Usage: ./extractCVE.sh <input1 [input2 ...]>"
	exit 2
fi
cve_output_dir="cve_entries"
cve_output=""
cve_patch_restart_list=".cve_patch_restart_list"
if [ ! -d "$cve_output_dir" ]; then
	mkdir $cve_output_dir
fi
if [ -f "$cve_patch_restart_list" ]; then
	echo "removing $cve_patch_restart_list"
       	rm $cve_patch_restart_list
fi       

for file; do
	echo "Reading $file"
	CVE=( $(grep -Po "CVE-\d{4}-\d{4}" $file | cut -d ',' -f 3 | sort -u) ) > /dev/null
	if [ -z CVE ]; then
		echo "No CVE lines matched in $file"
		continue       
	fi
	for CVEID in "${CVE[@]}" 
	do
		echo $CVEID
		cve_output="${CVEID}"
		cve_output_path="./$cve_output_dir/$cve_output"
		year=( $(echo $CVEID |cut -d '-' -f 2 ) )
	#	echo $year
		xmlFileName="nvdcve-2.0-$year.xml"
		if [ ! -f $xmlFileName ]; then
			echo "You don't have $xmlFileName!"
			echo "Let me retrieve that for you..."
			wget  -q --show-progress "https://static.nvd.nist.gov/feeds/xml/cve/2.0/$xmlFileName.zip" && unzip -q "$xmlFileName.zip" && rm -f "$xmlFileName.zip"
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
		if [ ! -f $cve_output_path ]; then
		sed -n "${startLine},${endLine}p" $xmlFileName > $cve_output_path
		echo "Creating $cve_output_path"
		fi
		restart=$(search_for_microsoft_vuln $startLine $endLine)
		patch="?"
		if [[ ! -z $restart ]]; then
			patch="True"	
		else
			patch_url=$(search_for_patch_url)	
			restart="?"
			if [[ ! -z $patch_url ]]; then
				patch="True"
			fi
		fi

		echo "$CVEID,$patch,$restart" >> "$cve_patch_restart_list"
	done

		echo "Input file: $file"
		echo "Cve file: $cve_patch_restart_list"
		echo "Please type an output file (default: a.out):"
		read output
		if [[ -z $output ]]; then
			output="a.out"
		fi
		python modifyCVS.py -i $file -o $output -c $cve_patch_restart_list
done

echo "Done!"
