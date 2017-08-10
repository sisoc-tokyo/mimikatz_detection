# Tracking Mimikatz by Sysmon and Elasticsearch

These are tools for detecting execution of Mimikatz.
We focus on dlls loaded by Mimikatz.
Our research details is here(coming soon).

You should procees the following steps.

1. Install sysmon and gather event logs on the targer computer.
   Please make sure that Event Id 7:Image loaded are recorded.

2. Export eventlogs as CSV format.
   detail procedure is here(coming soon).

3. Create dll lists which shuld be detected.
   You can do this by using tool "SysmonParser".
   Or you can also use existing dll lists created by us.

Useage:
java -jar sysmonParser.jar -d {input dir path} {output dir path}
input dir path: Specify full path where input csv files are exist.
output dir path:Specify full path where you want to output results.

Example:
java -jar sysmonParser.jar -d /var/tmp/sysmon/input /var/tmp/sysmon/output

About result files:
xxxxxxxxxx

4. Detect dlls by compared with dll lists and sysmon event logs on your real environment.
You can do this by using tool "SysmonDetecter".

Useage:
java -jar SysmonDetecter.jar {input dir path} {dll list path} {result file path}

Exampls:
java -jar SysmonDetecter.jar /var/tmp/sysmon/input　/var/tmp/sysmon/dlllist.txt /var/tmp/sysmon/output/result.csv

