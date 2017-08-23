# Tracking mimikatz by Sysmon and Elasticsearch(Python Tool)
This tool is for detecting mimikatz activity using elasticsearch.

Requirements:
You can access elasticsearch server that gather sysmon logs(Event ID 7).

Notes:
This tool is just example.
According to Elasticsearch, elasticsearch doesn't return more than 10,000 results.
<a href="https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-from-size.html">From / Size</a>
If there are more than 10,000 result that hit dll, this tool can't search logs completely.

Usage: python sysmon_mimi_detect your_ElasticserchServer_Address your_ElasticsearchServer_Port