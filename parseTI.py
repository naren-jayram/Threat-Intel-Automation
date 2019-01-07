""" 
Objective: This module is to parse Threat Intel data coming from Critical Stack Intel feeds
"""

import os
import re
import datetime
import json

#Custom modules
import writeCSV
import mod_time

#Start of Configuration
with open('config.json') as configuration:
    ti_config = json.load(configuration)
graylog_host = ti_config['GRAYLOG_HOST']
temp_directory = ti_config['TEMP_DIRECTORY']
feed_directory = ti_config['FEED_DIRECTORY']
# End of Configuration

#Variables
dedup_file = temp_directory + 'dedup.csv'
cef_file = temp_directory + 'cef.txt'
new_feeds_file = temp_directory + 'new_feeds.txt'
#End of Variables

#Function to parse temp files coming from Critical Stack Intel
def parse():
    # This will contribute to CEF <start> field in UTC
    curTime = datetime.datetime.utcnow()
    utcTime = str(curTime)
    cefStart = utcTime[0:19] + " UTC"

    # This will contribute to CEF <time> in UTC
    month = curTime.strftime("%B")
    cefMonth = month[0:3]
    cefTime = cefMonth + " " + curTime.strftime("%d %H:%M:%S")

    utc_date = curTime.strftime("%Y-%m-%d")

    completeIndicators = []  # This will hold the complete indicators from all the feeds
    completeIOC = []  # This will hold the complete IoC
    completeIOCType = []  # This will hold the complete IoC type
    completeFeedURL = []  # This will hold the complete feed URLs
    completeFeedName = []  # This will hold the complete feed names
    count = []  # This will hold complete IoC feed overlap count


    new_feed_list = mod_time.new_ti_feed_files()                            # This will pull the latest filenames from the feedDirectory (Directory name: .cache)
    print ("New Feeds: %s" %new_filename_list)
    if not new_feed_list:
        print("I will not parse Threat Intel Feeds due to non-availability of new/latest TI feeds...")
    else:
        with open(new_feeds_file, 'w+') as new_feeds:
            for feed_name in new_feed_list:
                new_feeds.write(feed_name+"\n")                             # This will write raw feed names to "new_feeds.txt"


        for filename in os.listdir(feed_directory):
            filename = feed_directory + filename
            print "Parsing " + str(filename)  # TEMP
            with open(filename, 'r') as file_content:
                if os.path.getsize(filename) > 0:  # If a file is not empty
                    for f_content in file_content:
                        iocString = str(f_content)
                        details = iocString.replace('\n', '')

                        if "#fields  indicator indicator_type  meta.source" in details:
                            continue

                        if details:  # If file content is not blank
                            if filename in "critical-stack-intel-126-bambenekconsulting.com-DGA-Domains.bro.dat":
                                fullIndicators = re.search("^([\w\.\-\/]+).*Intel::(.*)[\t]+.*,(.*)", details)

                                try:
                                    ioc = fullIndicators.groups()[0]
                                    iocType = fullIndicators.groups()[1]
                                    feedURL = fullIndicators.groups()[2]

                                except:
                                    iocTemp = str(details)
                                    ioc = iocTemp.replace('\n', '').replace('\t', '')
                                    iocType = "n/a"
                                    feedURL = "n/a"


                            elif filename in "critical-stack-intel-26-bambenekconsulting.com-C-C-Domains.bro.dat" or filename in "critical-stack-intel-2-bambenekconsulting.com-C-C-IPs.bro.dat":
                                fullIndicators = re.search("^([\w\.\-\/]+).*Intel::(.*)\\t.*(http.*|https.*)",
                                                           details)
                                # fullIndicators = re.search("^([\w\.\-\/]+).*Intel::(.*)[\s]+ .*(http.*|https.*)",details)

                                try:
                                    ioc = fullIndicators.groups()[0]
                                    iocType = fullIndicators.groups()[1]
                                    feedURL = fullIndicators.groups()[2]

                                except:
                                    iocTemp = str(details)
                                    ioc = iocTemp.replace('\n', '').replace('\t', '')
                                    iocType = "n/a"
                                    feedURL = "n/a"


                            elif filename in "critical-stack-intel-23-Malware-Domains.bro.dat":
                                fullIndicators = re.search("^([\w\.\-\/]+).*Intel::(.*)[\s]+(.*),.*", details)

                                try:
                                    ioc = fullIndicators.groups()[0]
                                    iocType = fullIndicators.groups()[1]
                                    feedURL = fullIndicators.groups()[2]

                                except:
                                    iocTemp = str(details)
                                    ioc = iocTemp.replace('\n', '').replace('\t', '')
                                    iocType = "n/a"
                                    feedURL = "n/a"


                            else:
                                fullIndicators = re.search("^([\w\.\-\/]+).*Intel::(.*)[\s]+(.*)", details)

                                try:
                                    ioc = fullIndicators.groups()[0]
                                    iocType = fullIndicators.groups()[1]
                                    feedURL = fullIndicators.groups()[2]

                                except:
                                    iocTemp = str(details)
                                    ioc = iocTemp.replace('\n', '').replace('\t', '')
                                    iocType = "n/a"
                                    feedURL = "n/a"

                            filenameFieldSegregation = re.search("(critical-stack-intel)-([\d]+)-(.*)\.bro.*",
                                                                 filename)  # This will segregate the <Feed Name> fields
                            feedName = filenameFieldSegregation.groups()[2]  # This will only pick Feed Name
                            completeIndicators.append([ioc, iocType, feedURL, feedName])
                            completeIOC.append(ioc)
                            completeIOCType.append(iocType)
                            completeFeedURL.append(feedURL)
                            completeFeedName.append(feedName)

                else:
                    print "File is empty"
                    continue


        # This will give feedname specific unique IoC count
        overlap = {}
        for ioc, feedname in zip(completeIOC, completeFeedName):
            overlap.setdefault(ioc, []).append(feedname)  # overlap = {ioc:[feedname1, feedname....]}

        for ioc in completeIOC:
            count.append(len(set(overlap[ioc])))  # help obtain count of unique feednames associated with an IoC

        for full_indicators, cnt in zip(completeIndicators, count):
            full_indicators.append(cnt)  # appending feedname specific unique IoC count to full_indicators

        for full_indicators in completeIndicators:
            full_indicators.append(utc_date)

        # this section will de-duplicate the indicators from the latest feeds
        results = []
        for writeIndicators in completeIndicators:
            ioc = str(writeIndicators[0]).lower()  # ioc in lower case
            results.append(writeIndicators)

        # this section will check for same pre-existing indicators in the CSV file. If new indicators not found in the CSV file, it will be written to csv file for manual lookups
        writeCSV.writeResults(results)


        #This section will convert individual IoC information to CEF compatible message
        with open(cef_file, 'w+') as cef_write:  
            with open (dedup_file,'r') as de_dup_complete:
                for indicator_details in de_dup_complete:
                    dedup_ioc = indicator_details[0]
                    dedup_ioc_type = indicator_details[1]
                    dedup_feed_url = indicator_details[2]
                    dedup_feed_name = indicator_details[3]
                    dedup_feed_overlap_count = indicator_details[4]

                    output = str("<117>%s critical-stack SyslogAlertForwarder: CEF:0|My Company|Threat Intelligence|1.0.0|n/a|n/a|n/a|indicator=%s indicator_type=%s feed_url=%s feed_name=%s feed_overlap_count=%s start=%s" %(cefTime, dedup_ioc, dedup_ioc_type, dedup_feed_url, dedup_feed_name, dedup_feed_overlap_count, cefStart))
                    cef_write.write(output+"\n")

        os.remove(dedup_file) # Deleting dedup.csv

        #This section will inject the CEF formatted IoC message to graylog
        os.system('cat /opt/critical-stack/frameworks/intel/temp/cef.txt |   while read -r line ; do echo "$line" | nc -v -t -w 100ms %s 12201;   done;' %graylog_host)