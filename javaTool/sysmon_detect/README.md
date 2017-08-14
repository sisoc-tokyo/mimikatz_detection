# A Java tool for detecting mimikatz from exported Sysmon event log
Detect mimikatz comparing Common DLL List with exported Sysmon event log.
This tool outputs processes that load all DLLs in Common DLL List and detection rate.

At first, please import this tool into your Eclipse.

Project name: sysmon_detect

Main Class: logparse.SysmonDetecter

Usage:
iputdirpath} {Common DLL List path} {outputdirpath} (-dr)
{inputdirpath}: Full path of directory where exported Sysmon event log files exsist. 
{Common DLL List path}: Full path of Common DLL List
{outputdirpath}: Full path of directory where you want to output result files.
-dr(optional): If you evaluate detection rate using Common DLL Lists specify this option. 

Example:
/Users/marikof/Documents/data/logs/ /Users/marikof/Documents/data/loadedDLLs/CommonDLLlist.csv /Users/marikof/Documents/data/results/ -dr

By Mariko Fujimoto
