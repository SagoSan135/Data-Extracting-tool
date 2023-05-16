#!/bin/bash

# Welcome to my project
# Sagi Saad
# DET = Data extraction tool

#This are configuration for colored text
GREEN='\033[0;32m'     
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color
PURPLE='\033[0;35m' 

# If statement that checks for root user
if [ "$EUID" -ne 0 ]
then
	echo "Please run as root"
	exit
fi

#this function is responsible to check for the file name the user specifies
function FileCheck() {
while true
do
# this is a testing idea - instead of making an infinite loop to check for a file name then give for the user the option to continue in
# the same menu, instead i want to make a variable to constantly be equal to zero, if the file exist then increase the variable by one
# thus breaking the menu infinite loop and and make progress automatically
	var1=0
	echo -e "\nIf you want to exit the program, please write \"exit\", if not then Enter the full path of the file\nFor example: $(pwd)/<FileName>"
	read file
	if [ $file == "exit" ]
	then
		echo -e "\nExiting program..."
		sleep 1
		exit
	elif [ -f $file ]
	then
		sleep 0.5
		echo -e "\nthe file ${GREEN}exists${NC}"
		sleep 1.5
		((var1++))
		break
	else
		sleep 0.5
		echo -e "\nthe file ${RED}does not exist or the path is wrong${NC}"
		sleep 1.5
	fi
done
}

#this function is responsible to check & download all neccessary tools
function ToolInstall() {
	echo -e "\nChecking if Foremost is installed..."
	sleep 1
	if [[ ! -z $(dpkg -s foremost 2>/dev/null) ]]
	then
		echo -e "${GREEN}It is installed${NC}"
		sleep 1
	else
		echo -e "It is ${RED}not installed${NC}\nDownloading tool..."
		sleep 1
		apt-get install foremost -y 2>&1 >/dev/null
	fi

	echo -e "\nChecking if Bulk-extractor is installed..."
	sleep 1
	if [[ ! -z $(dpkg -s bulk-extractor 2>/dev/null) ]]
	then
		echo -e "${GREEN}It is installed${NC}"
		sleep 1
	else
		echo -e "It is ${RED}not installed${NC}\nDownloading tool..."
		sleep 1
		apt-get install bulk-extractor -y 2>&1 >/dev/null
	fi
	
	echo -e "\nChecking if Bulk-extractor-dbgsym is installed..."
	sleep 1
	if [[ ! -z $(dpkg -s bulk-extractor-dbgsym 2>/dev/null) ]]
	then
		echo -e "${GREEN}It is installed${NC}"
		sleep 1 
	else
		echo -e "It is ${RED}not installed${NC}\nDownloading tool..."
		sleep 1
		apt-get install bulk-extractor-dbgsym -y 2>&1 >/dev/null
	fi
	
	echo -e "\nChecking if Strings is installed..."
	sleep 1
	if [[ ! -z $(dpkg -s binutils 2>/dev/null) ]]
	then
		echo -e "${GREEN}It is installed${NC}"
		sleep 1
	else
		echo -e "It is ${RED}not installed${NC}\nDownloading tool..."
		sleep 1
		apt-get install binutils -y 2>&1 >/dev/null
	fi
	
	echo -e "\nChecking if Tree is installed..."
	sleep 1
	if [[ ! -z $(dpkg -s tree 2>/dev/null) ]]
	then
		echo -e "${GREEN}It is installed${NC}"
		sleep 1
	else
		echo -e "It is ${RED}not installed${NC}\nDownloading tool..."
		sleep 1
		apt-get install tree -y 2>&1 >/dev/null
	fi
	
	echo -e "\nChecking if Zip is installed..."
	sleep 1
	if [[ ! -z $(dpkg -s zip 2>/dev/null) ]]
	then
		echo -e "${GREEN}It is installed${NC}"
		sleep 1
	else
		echo -e "It is ${RED}not installed${NC}\nDownloading tool..."
		sleep 1
		apt-get install zip -y 2>&1 >/dev/null
	fi

	echo -e "\nChecking if Volatility is installed..."
	sleep 1
	if [[ $(ls | grep VolTool) == "VolTool" ]]
	then
		echo -e "${GREEN}It is installed${NC}"
		sleep 1
	else
		echo -e "It is ${RED}not installed${NC}\nDownloading tool..."
		sleep 1
		mkdir VolTool
		wget -P VolTool http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip 2>/dev/null
		unzip VolTool/volatility_2.6_lin64_standalone.zip -d VolTool 2>&1 >/dev/null 
	fi

	sleep 1
	echo -e "\nAll neccessary tools ${GREEN}have been installed${NC}\n"
	sleep 2
}

#this function is responsible to extract data from the specified file
function DataExtraction() {
	echo -e "Extracting data, please wait..."
# DEVELOPER NOTE ==> i want to make a spinning downloading animation, but could'nt quite make it work properly
	sleep 1
	echo -e "\nExecuting foremost"
	sleep 0.5
	foremost -t all $file 2>&1 >/dev/null
	sleep 1
	
	echo -e "\nExecuting bulk-extractor"
	sleep 0.5
	bulk_extractor $file -o Results 2>&1 >/dev/null
	sleep 1
	
	echo -e "\nExecuting strings"
	sleep 0.5

	ReadableData
	
	sleep 1	
# DEVELOPER NOTE ==> and here i make the kill <animation function> so the animation stops
# <=== Adonis come on help me with that cool animation bro ===>
}

#this function is responsible to check for a potentional network traffic information 
function PacketsCheck() {
	echo -e "\nChecking for a possible network traffic file\n"
	sleep 1
	if [[ $(ls ./Results | grep "packets.pcap") == "packets.pcap" ]]
	then
		echo -e "Network traffic file ${GREEN}has been found${NC}\n"
		sleep 1
		path=$(pwd)
		size=$(ls Results/packets.pcap -lh | awk '{print $5}')
		echo -e "The full path is: ${GREEN}$path/RESULTS/packets.pcap and the size is $size${NC}\n"
		sleep 1
	else
		echo -e "Network traffic file ${RED}has not been found${NC}\n"
		sleep 1
	fi
}

#function thats resposbile to extract human readable data
function ReadableData() {
	mkdir Strings
	strings $file | grep .exe >> Strings/exe.txt
	strings $file | grep user >> Strings/usernames.txt
	strings $file | grep password >> Strings/passwords.txt
}

# This will check if the file is a mem extension thus executing volatility 
function MemFileCheck() {
# This var2 will act as a variable to break a loop that's built ahead
	var2=0
# This VarTool will act as a variable to execute volatility if were dealing with a memory file	
	varTool=0
	echo -e "\nYour file name is:"
	echo "$file" | sed "s/\// /g" | awk '{print $(NF-0)}'
	sleep 1
	
	if [[ -z $(echo -e "$file" | grep ".mem") ]]
	then
#		echo -e "First statement check - meaning the grep is empty"
		echo -e "\nIt is ${RED}not a memory file${NC}"
		sleep 1
	else
#		echo -e "Second statement check - meaning the grep has captured the .mem file extension"
#		echo -e "$file" | sed "s/\// /g" | awk '{print $(NF-0)}' | grep ".mem"
		echo -e "\nIt is ${GREEN}a memory file${NC}"
# This is an if statement variable that will execute volatusage function thus extracting more data from the .mem file
		((varTool++))
		sleep 1
	fi
# This var2 is responsible to exit the infinite loop inside the menu loop	
	((var2++))
}

# This is the volatility usage if the file is .mem
function VolatUsage() {
	echo -e "\nGetting profile information of the memory file"
	sleep 1

	profile=$(./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file imageinfo | grep "Suggested Profile(s)" | cut -d : -f2 | awk '{print $1}' | cut -d , -f1)
	echo -e "\n${GREEN}the profile is: $profile${NC}\n"
	sleep 1
	
	mkdir VolData
	echo "IMPORTANT NOTE - Some text files can be empty, it could be because the information was missing from the file, or the profile did not match" > VolData/README.txt
	echo -e "\nAttempting to extract proccess list...\n"
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file --profile=$profile pslist >> VolData/pslist.txt
	
	echo -e "\nAttempting to extract connections that were active during operation...\n"
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file --profile=$profile netscan >> VolData/netscan.txt

	
	echo -e "\nAttempting to extract registry hive files...\n"
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file --profile=$profile hivelist >> VolData/hivelist.txt

	echo -e "\nAttempting to extract registry userassist information..."
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file --profile=$profile userassist >> VolData/userassist.txt
	
	echo -e "\nAttempting to extract registry consoles information...\n"
	sleep 1
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file --profile=$profile consoles >> VolData/consoles.txt
	
	echo -e "\nAttempting to extract user and password information from registry files...\n"
	sleep 1.5
	sam=$(./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file --profile=$profile hivelist | grep "\SAM" | awk '{print $1}')
	system=$(./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file --profile=$profile hivelist | grep "\SYSTEM" | awk '{print $1}')
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file --profile=$profile hashdump -y $system -s $sam > VolData/hashes.txt
#	IMPORTANT NOTE - FIRST OF ALL I USE hashdump -y SYSTEM -s SAM > VolData/hashes.txt

	echo -e "\nAttempting to extract account of the computer...\n"
	sleep 1.5
	./VolTool/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone -f $file --profile=$profile printkey -K "SAM\Domains\Account\Users\Names" >> VolData/CompUsers.txt
}

# this function is responsible to make a conclusion of the whole information that's been gathered
function conclusion() {
	sleep 2
	mkdir Report
	sleep 1
	
	echo -e "\nData has been collected ${GREEN}succesfuly${NC} on $(date)"
	echo -e "Data has been collected on $(date)" >> Report/Report.txt
	sleep 2
	echo -e "\nMaking a report file"
	sleep 1
	echo -e "Directory Results: $(tree Results|tail -1)" >> Report/Report.txt
	echo -e "Directory output: $(tree output|tail -1)" >> Report/Report.txt
	echo -e "Directory Strings: $(tree Strings|tail -1)" >> Report/Report.txt
	echo -e "Directory VolData: $(tree VolData|tail -1)" >> Report/Report.txt
	sleep 1
	echo -e "\n${GREEN}Report file has been written${NC}\n"
	sleep 1
	cat Report/Report.txt
	sleep 5

	echo -e "\nMaking a zip report file...\n"
	sleep 0.5
	zip -r Report.zip output Results Strings VolData Report 2>&1 >/dev/null
	sleep 0.5
	echo -e "${GREEN}Succesfuly made a zip file${NC}"
}

# --------------------------- END OF FUNCTIONS ---------------------------




# --------------------------- START OF THE PROGRAM ---------------------------



#Eithan's data extraction tool - EDE tool

# This while loop is responsible to call the tool instalation function
while true
do
	echo -e "\nWelcome to EDE - The data extraction tool\nFirst of all we have to check and download neccessary tools"
	echo -e "What would you like to do?\n1) Continue\n2) Exit\n"
	read answer1
	
	if [ $answer1 -eq 1 ]
	then
		ToolInstall
		break
	elif [ $answer1 -eq 2 ]
	then
		echo -e "Exiting tool..."
		sleep 1
		exit
	else
		echo -e "\n${RED}Wrong input${NC}, choose one of the options on the menu\n"
	fi
done

#This loop is responsible to check the existense of the file
while true
do
	echo -e "EDE tool is capable of extracting all kinds of information from an image file\nFirst of all we have to check if the file exists"
	echo -e "1) Get a file name\n2) Exit\n"
	read answer2
	
	if [ $answer2 -eq 1 ]
	then
		sleep 0.5
		FileCheck
	elif [ $answer2 -eq 2 ]
	then
		echo -e "Exiting tool..."
		sleep 1
		exit
	else
		echo -e "\n${RED}Wrong input${NC}, choose one of the options on the menu\n"
	fi
# as noted before, instead of giving three options to the user, one of them being to exit this loop, i've made this variable
# to exit automatically from this while loop as long as the user is progressing correctly (meaning giving the coorect path and file)
# it is implemented in line 28
	if [ $var1 -ne 0 ]
	then
		break
	fi
done

# This loop is responsible to check if the file that the user specified is HDD or RAM file, its done through automation by checking the 
# extension name
while true
do
	echo -e "\nAfter making sure the file exists, let's check if it's a memory file\n1) Approve check\n2) Exit\n"
	read answer5
	
	if [ $answer5 -eq 1 ]
	then
		echo -e "\nChecking..."
		sleep 1
		MemFileCheck
	elif [ $answer5 -eq 2 ]
	then
		echo -e "Exiting tool..."
		sleep 1
		exit
	else
		echo -e "\n${RED}Wrong input${NC}, choose one of the options on the menu\n"
	fi
# as noted before, this variable is responsible to break this loop automaticaly istead of giving the option to the user
# it is first implemented at line 198
	if [ $var2 -eq 1 ]
	then
		break
	fi
done


#This loop is responsible to extract all kinds of data like foremost, bulk-extractor etc...
while true
do
	echo -e "\nWould you like to extract the data from the file?\n1) Yes\n2) No - Exit\n"
	read answer3
	
	if [ $answer3 -eq 1 ]
	then
		DataExtraction
		sleep 1.5
		break
	elif [ $answer3 -eq 2 ]
	then
		echo -e "\nExiting tool..."
		sleep 1
		exit
	else
		echo -e "\n${RED}Wrong input${NC}, choose one of the options on the menu\n"
	fi
done

#This loop checks for a possible extracted packets file
while true
do
	echo -e "\nWe might have extracted network traffic information, would you like to check it?"
	echo -e "1) Yes\n2) No - Exit"
	read answer4

	if [ $answer4 -eq 1 ]
	then
		sleep 1
		PacketsCheck
		break
	elif [ $answer -eq 2 ]
	then
		echo -e "\Exiting tool..."
		sleep 1
		exit
	fi
done

# if statement that will execute volatility and extract more information if we're dealing with RAM file
if [ $varTool -eq 1 ]
then
	echo "Because the file is a MEM file, we will extract more information"
	VolatUsage
else
	echo "Because the file is not a MEM file, we are done extracting information from it"
fi

sleep 1.5
conclusion

echo -e "${GREEN}Project is done${NC}"
