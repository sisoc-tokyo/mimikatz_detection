# Tracking mimikatz by Sysmon and Elasticsearch

These are tools for helping to detect execution of mimikatz using Sysmon logs.
We focus on dlls loaded by mimikatz.
Our research details is the following.

<a href="https://hitcon.org/2017/CMT/agenda" target="blank">HITCON Community 2017 DAY 2 (8/26): Tracking mimikatz by Sysmon and Elasticsearch</a>.


We provide the DLL Lists for helping mimikatz detection.

https://github.com/sisoc-tokyo/mimikatz_detection/tree/master/DLLLists

- DLLlist_{environment name}-mimi{yyyymmdd}.csv: DLL Lists loaded by mimikatz in specific environment
- CommonDLLlist.csv: DLL Lists that is commonly loaded regardless of Windows and mimikatz versions
- AllDLLs.csv: All results of mimikatz DLL loading of all tested Windows and mimikatz versions

We provide the following tools.
- Tools to create Common DLL List from exported event logs and detect processes that matches the Common DLL List (Java)

https://github.com/sisoc-tokyo/mimikatz_detection/tree/master/javaTool

- A tool to detect processes that matches Common DLL List from Elasticsearch results (Python 3)

https://github.com/sisoc-tokyo/mimikatz_detection/tree/master/pythonTool

Before using our tools, you should procees the following steps.

- Install sysmon and gather event logs on the computer which you want to investigate.
  Please make sure that Event Id 7:Image loaded are recorded.

- To know the details of tools, please refer README for each tool.

Published by
Wataru Matsuda & Mariko Fujimoto

