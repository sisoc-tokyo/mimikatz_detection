These are tools to create Common DLL List from event logs and detect processes that matches the Common DLL List (Java)
Tools are provided as Eclipse project format, so you can import these tools into Eclipse.
We provide two tools:

<a href="https://github.com/sisoc-tokyo/mimikatz_detection/tree/master/javaTool/CreateCommonDLLList">CreateCommonDLLList</a>
Parse CSV files exported from Sysmon event log. 
This tool outputs DLLs loaded by mimikatz and Create Common DLL List.

<a href="https://github.com/sisoc-tokyo/mimikatz_detection/tree/master/javaTool/sysmon_detect">sysmon_detect</a>
Detect mimikatz comparing Common DLL List with exported Sysmon event log.
This tool outputs processes that load all DLLs in Common DLL List and detection rate.


Before using the tools, you should export Sysmon eventlogs as CSV format.
Detail procedure is here(coming soon).

