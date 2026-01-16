#!/bin/bash

command1="host"
input_file="subdomains.txt"

#Colours 
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NONE='\033[0m' 

#CTRL+C to quit
trap 'echo -e "\n${RED}Interrupted by user. Exiting...${NONE}"; exit 130' SIGINT

#check if file exists
if [[ ! -f "$input_file" ]]; then
    echo -e "${RED}File not found:${NONE} $input_file"
    exit 1
fi

#Read and run file
while IFS= read -r command2 || [[ -n "$command2" ]]; do
    echo -e "${YELLOW}Running:${NONE} ${BLUE}$command2${NONE}"

    $command1 "$command2" 2>&1 | while IFS= read -r line; do
        if [[ "$line" == *"not found"* || "$line" == *"NXDOMAIN"* ]]; then
            echo -e "${RED}$line${NONE}"
        else
            echo -e "${GREEN}$line${NONE}"
        fi
    done

done < "$input_file"

