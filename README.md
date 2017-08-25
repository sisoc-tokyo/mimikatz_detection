# Tracking mimikatz by Sysmon and Elasticsearch

These are tools for helping to detect execution of mimikatz.
We focus on dlls loaded by mimikatz.
Our research details is the following.
<a href="https://hitcon.org/2017/CMT/agenda" target="blank">Tracking mimikatz by Sysmon and Elasticsearch</a>.

We provide the following tools.
- Tools to create Common DLL List from event logs and detect processes that matches the Common DLL List (Java)
https://github.com/sisoc-tokyo/mimikatz_detection/tree/master/javaTool

- A tool to detect processes that matches Common DLL List from Elasticsearch results (Python 3)
https://github.com/sisoc-tokyo/mimikatz_detection/tree/master/pythonTool

Before using our tools, you should procees the following steps.

- Install sysmon and gather event logs on the computer which you want to investigate.
  Please make sure that Event Id 7:Image loaded are recorded.

- To know the details of tools, please refer README for each tool.

Published by
Wataru Matsuda & Mariko Fujimoto

