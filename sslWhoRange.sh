#!/bin/bash
while getopts ":f:p:" flag
do
    case "${flag}" in
	f) rangeFile=${OPTARG};;
	p) port=${OPTARG};;
    esac
done

if [ -z "${rangeFile}" ] || [ -z "${port}" ]
then 
    echo "Usage: $0 -f [rangeFile] -p [port]"
    exit
fi

while read p; do
    sslWho -p "${port}" -r "$p"
done < "${rangeFile}"
