#!/bin/bash

# Data Extraction Tool (DET)
# Author: Sagi Saad

# Configuration for colored text
GREEN='\033[0;32m'     
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color
PURPLE='\033[0;35m' 

# Check for root user
if [ "$EUID" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

# Function to check for the file name the user specifies
function FileCheck() {
	while true; do
		echo -e "\nIf you want to exit the program, please write \"exit\", if not then Enter the full path of the file\nFor example: $(pwd)/<FileName>"
		read -r file
		if [ "$file" == "exit" ]; then
			echo -e "\nExiting program..."
			sleep 1
			exit 0
		elif [ -f "$file" ]; then
			sleep 0.5
			echo -e "\nThe file ${GREEN}exists${NC}"
			sleep 1.5
			break
		else
			sleep 0.5
			echo -e "\nThe file ${RED}does not exist or the path is wrong${NC}"
			sleep 1.5
		fi
	done
}

# Function to check & download all necessary tools
function ToolInstall() {
	local tools=(
		"foremost:foremost"
		"bulk-extractor:bulk-extractor"
		"bulk-extractor-dbgsym:bulk-extractor-dbgsym"
		"Strings (binutils):binutils"
		"Tree:tree"
		"Zip:zip"
	)
	
	for tool_pair in "${tools[@]}"; do
		IFS=':' read -r display_name package_name <<< "$tool_pair"
		echo -e "\nChecking if $display_name is installed..."
		sleep 1
		if dpkg -s "$package_name" &>/dev/null; then
			echo -e "${GREEN}It is installed${NC}"
			sleep 1
		else
			echo -e "It is ${RED}not installed${NC}\nDownloading tool..."
			sleep 1
			apt-get install "$package_name" -y &>/dev/null
		fi
	done

	echo -e "\nChecking if Volatility is installed..."
	sleep 1
	if [ -d "VolTool" ]; then
		echo -e "${GREEN}It is installed${NC}"
		sleep 1
	else
		echo -e "It is ${RED}not installed${NC}\nDownloading tool..."
		sleep 1
		mkdir VolTool
		wget -P VolTool http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip 2>/dev/null
		unzip VolTool/volatility_2.6_lin64_standalone.zip -d VolTool &>/dev/null 
	fi

	sleep 1
	echo -e "\nAll necessary tools ${GREEN}have been installed${NC}\n"
	sleep 2
}

# Function to extract data from the specified file
function DataExtraction() {
	echo -e "Extracting data, please wait..."
	sleep 1
	
	echo -e "\nExecuting foremost"
	sleep 0.5
	foremost -t all "$file" &>/dev/null
	sleep 1
	
	echo -e "\nExecuting bulk-extractor"
	sleep 0.5
	bulk_extractor "$file" -o Results &>/dev/null
	sleep 1
	
	echo -e "\nExecuting strings"
	sleep 0.5
	ReadableData
	sleep 1	
}

# Function to check for potential network traffic information 
function PacketsCheck() {
	echo -e "\nChecking for a possible network traffic file\n"
	sleep 1
	if [ -f "./Results/packets.pcap" ]; then
		echo -e "Network traffic file ${GREEN}has been found${NC}\n"
		sleep 1
		local path=$(pwd)
		local size=$(ls -lh Results/packets.pcap | awk '{print $5}')
		echo -e "The full path is: ${GREEN}$path/Results/packets.pcap and the size is $size${NC}\n"
		sleep 1
	else
		echo -e "Network traffic file ${RED}has not been found${NC}\n"
		sleep 1
	fi
}

# Function to extract human readable data
function ReadableData() {
	mkdir -p Strings
	strings "$file" | grep .exe >> Strings/exe.txt
	strings "$file" | grep user >> Strings/usernames.txt
	strings "$file" | grep password >> Strings/passwords.txt
}

# Check if the file is a .mem extension
function MemFileCheck() {
	echo -e "\nYour file name is:"
	basename "$file"
	sleep 1
	
	if [[ "$file" == *.mem ]]; then
		echo -e "\nIt is ${GREEN}a memory file${NC}"
		is_mem_file=1
		sleep 1
	else
		echo -e "\nIt is ${RED}not a memory file${NC}"
		is_mem_file=0
		sleep 1
	fi
}

# Volatility usage if the file is .mem
function VolatUsage() {
	echo -e "\nGetting profile information of the memory file"
	sleep 1

	local profile=$(./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" imageinfo | grep "Suggested Profile(s)" | cut -d : -f2 | awk '{print $1}' | cut -d , -f1)
	echo -e "\n${GREEN}The profile is: $profile${NC}\n"
	sleep 1
	
	mkdir -p VolData
	echo "IMPORTANT NOTE - Some text files can be empty, it could be because the information was missing from the file, or the profile did not match" > VolData/README.txt
	
	echo -e "\nAttempting to extract process list...\n"
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" --profile="$profile" pslist >> VolData/pslist.txt
	
	echo -e "\nAttempting to extract connections that were active during operation...\n"
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" --profile="$profile" netscan >> VolData/netscan.txt

	echo -e "\nAttempting to extract registry hive files...\n"
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" --profile="$profile" hivelist >> VolData/hivelist.txt

	echo -e "\nAttempting to extract registry userassist information...\n"
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" --profile="$profile" userassist >> VolData/userassist.txt
	
	echo -e "\nAttempting to extract registry consoles information...\n"
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" --profile="$profile" consoles >> VolData/consoles.txt
	
	echo -e "\nAttempting to extract user and password information from registry files...\n"
	sleep 1.5
	local sam=$(./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" --profile="$profile" hivelist | grep "\\SAM" | awk '{print $1}')
	local system=$(./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" --profile="$profile" hivelist | grep "\\SYSTEM" | awk '{print $1}')
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" --profile="$profile" hashdump -y "$system" -s "$sam" > VolData/hashes.txt

	echo -e "\nAttempting to extract account of the computer...\n"
	sleep 1.5
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f "$file" --profile="$profile" printkey -K "SAM\Domains\Account\Users\Names" >> VolData/CompUsers.txt
}

# Function to make a conclusion of the gathered information
function conclusion() {
	sleep 2
	mkdir -p Report
	sleep 1
	
	echo -e "\nData has been collected ${GREEN}successfully${NC} on $(date)"
	echo -e "Data has been collected on $(date)" >> Report/Report.txt
	sleep 2
	echo -e "\nMaking a report file"
	sleep 1
	
	[ -d "Results" ] && echo -e "Directory Results: $(tree Results 2>/dev/null | tail -1)" >> Report/Report.txt
	[ -d "output" ] && echo -e "Directory output: $(tree output 2>/dev/null | tail -1)" >> Report/Report.txt
	[ -d "Strings" ] && echo -e "Directory Strings: $(tree Strings 2>/dev/null | tail -1)" >> Report/Report.txt
	[ -d "VolData" ] && echo -e "Directory VolData: $(tree VolData 2>/dev/null | tail -1)" >> Report/Report.txt
	
	sleep 1
	echo -e "\n${GREEN}Report file has been written${NC}\n"
	sleep 1
	cat Report/Report.txt
	sleep 5

	echo -e "\nMaking a zip report file...\n"
	sleep 0.5
	zip -r Report.zip output Results Strings VolData Report 2>/dev/null
	sleep 0.5
	echo -e "${GREEN}Successfully made a zip file${NC}"
}

# --------------------------- END OF FUNCTIONS ---------------------------

# --------------------------- START OF THE PROGRAM ---------------------------

# Main program variables
is_mem_file=0

# Tool installation loop
while true; do
	echo -e "\nWelcome to EDE - The data extraction tool\nFirst of all we have to check and download necessary tools"
	echo -e "What would you like to do?\n1) Continue\n2) Exit\n"
	read -r answer1
	
	if [ "$answer1" -eq 1 ] 2>/dev/null; then
		ToolInstall
		break
	elif [ "$answer1" -eq 2 ] 2>/dev/null; then
		echo -e "Exiting tool..."
		sleep 1
		exit 0
	else
		echo -e "\n${RED}Wrong input${NC}, choose one of the options on the menu\n"
	fi
done

# File existence check loop
while true; do
	echo -e "EDE tool is capable of extracting all kinds of information from an image file\nFirst of all we have to check if the file exists"
	echo -e "1) Get a file name\n2) Exit\n"
	read -r answer2
	
	if [ "$answer2" -eq 1 ] 2>/dev/null; then
		sleep 0.5
		FileCheck
		break
	elif [ "$answer2" -eq 2 ] 2>/dev/null; then
		echo -e "Exiting tool..."
		sleep 1
		exit 0
	else
		echo -e "\n${RED}Wrong input${NC}, choose one of the options on the menu\n"
	fi
done

# Memory file check loop
while true; do
	echo -e "\nAfter making sure the file exists, let's check if it's a memory file\n1) Approve check\n2) Exit\n"
	read -r answer5
	
	if [ "$answer5" -eq 1 ] 2>/dev/null; then
		echo -e "\nChecking..."
		sleep 1
		MemFileCheck
		break
	elif [ "$answer5" -eq 2 ] 2>/dev/null; then
		echo -e "Exiting tool..."
		sleep 1
		exit 0
	else
		echo -e "\n${RED}Wrong input${NC}, choose one of the options on the menu\n"
	fi
done

# Data extraction loop
while true; do
	echo -e "\nWould you like to extract the data from the file?\n1) Yes\n2) No - Exit\n"
	read -r answer3
	
	if [ "$answer3" -eq 1 ] 2>/dev/null; then
		DataExtraction
		sleep 1.5
		break
	elif [ "$answer3" -eq 2 ] 2>/dev/null; then
		echo -e "\nExiting tool..."
		sleep 1
		exit 0
	else
		echo -e "\n${RED}Wrong input${NC}, choose one of the options on the menu\n"
	fi
done

# Network traffic check loop
while true; do
	echo -e "\nWe might have extracted network traffic information, would you like to check it?"
	echo -e "1) Yes\n2) No - Exit"
	read -r answer4

	if [ "$answer4" -eq 1 ] 2>/dev/null; then
		sleep 1
		PacketsCheck
		break
	elif [ "$answer4" -eq 2 ] 2>/dev/null; then
		echo -e "\nExiting tool..."
		sleep 1
		exit 0
	else
		echo -e "\n${RED}Wrong input${NC}, choose one of the options on the menu\n"
	fi
done

# Execute volatility if dealing with RAM file
if [ "$is_mem_file" -eq 1 ]; then
	echo "Because the file is a MEM file, we will extract more information"
	VolatUsage
else
	echo "Because the file is not a MEM file, we are done extracting information from it"
fi

sleep 1.5
conclusion

echo -e "${GREEN}Project is done${NC}"
