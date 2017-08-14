# A Java tool for Creating CommonDLLList
Parse CSV files exported from Sysmon event log. 
This tool outputs DLLs loaded by mimikatz and Create Common DLL List.

At first, please import this tool into your Eclipse.

Project name: CreateCommonDLLList

Main Class: logparse.SysmonParser

Usage:
-d {inputdirpath} {outputdirpath}

{inputdirpath}: Full path of directory where exported Sysmon event log files exsist. 

{outputdirpath}: Full path of directory where you want to output result files.

Example:
-d /Users/marikof/Documents/data/ImageloadedEvent /Users/marikof/Documents/data/loadedDLLs/

By Mariko Fujimoto
