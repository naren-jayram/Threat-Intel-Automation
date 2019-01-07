# Threat Intel Automation

Threat Intel Automation using Graylog and Critical-Stack-Intel

To help automate basic statistical analysis on threat Intel data/feeds by parsing raw *Critical Stack Intel* data

Indicators of Compromise (IoC) will be used in Graylog lookup tables to enrich messages coming from different data/log source to Graylog

Deduped/Enriched IoCs will be injected to Graylog. If you don't wish this feature, you can disable last line in parseTI.py

**Overlap Test:** This will compare the IoC with different threat Intel feeds and gives a count. Bigger the count, IoC is more trustable.

### Use Cases
* IoC lookup in historical graylog data to check for suspicious traces in the network
* IoC trend analysis (In Graylog)
* In-house repository for Threat Intel 
* Compliments Threat hunting


### Prerequisites

* Access to Graylog GUI
* Critical Stack Intel installation. 
* Create an account and subscribe to Threat Intel feeds. https://intel.criticalstack.com/
* Flask, Gunicorn, NGINX; for installation/configuration refer *REST API.docx*
* Replace *domain_name* with proper domain name in *nginx.conf*
* Input appropriate values in *config.jsom*


### Directories Used

* Critical Stack Intel stores the raw TI data here:	/opt/critical-stack/frameworks/intel/.cache/
* All the Output files resides here: /opt/critical-stack/frameworks/intel/temp/
* Currently contributing feed names are stored here: /opt/critical-stack/frameworks/intel/temp/new_feeds.txt


### Usage
**Manual**
```sh
python ti_rest.py
```
**Automation**
```sh
Create a service. Refer: ti_rest.py
```

**Removing Old IoCs as per the retention days (Note: All the IoCs resides here: TI_ADDR.csv.dedup, TI_URL.csv.dedup, TI_HASH.csv.dedup)**
```sh
python old_ioc_cleanup.py
```

### Outcome
**You will see few/all of the below fields in Graylog GUI if either src,dst or request field in Graylog matches with IoC from Threat Intel feeds.**
> ti_feed_name, ti_feed_overlap_count, ti_feed_overlap_count_description, ti_lookup_src, ti_lookup_dst, ti_lookup_req, ti_ioc_feed_date

**If you are injecting all IoCs  to Graylog, you will observe below fields in Graylog GUI (in addition to above fields):**
> indicator, indicator_type, feed_url, feed_name, feed_overlap_count
                

### Note
* This script is written in v2.7.14
* This script will only support Unix environment. If you need to run this on Windows platform, please enable Windows Subsystem for Linux / Install Ubuntu app from the windows store
* For details on Rest API, refer *REST API.docx*
* For details on Graylog Lookup Tables, refer *Lookup Table Configuration.docx* file in *Docs* folder
* For details on Graylog Pipeline rules, refer *Graylog Pipeline -MultiValue_Lookup_Table* in *Docs* folder
* Place all the scripts in /opt/scripts/ThreatIntel
 

### TEST
```sh
curl http://localhost:8000/addr?addr=217.170.197.89
{"ioc_details":{"date":"2018-11-15","feed_name":"Known-Tor-Exit-Nodes","feed_overlap_count":"1","feed_url":"https://www.dan.me.uk/torlist/","ioc":"217.170.197.89","ioc_type":"ADDR"}}
```

### Courtesy
##### [criticalstack] https://intel.criticalstack.com/