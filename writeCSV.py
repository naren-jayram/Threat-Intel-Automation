""" 
Objective:
This module provides basic functions like writing IoCs to CSV, looping through results and finding the right file to write to and finally deduplicating entries in final CSV file
"""

from more_itertools import unique_everseen
import os
import csv
import re
import json


# Start of Configuration
with open('config.json') as configuration:
    ti_config = json.load(configuration)
temp_directory = ti_config['TEMP_DIRECTORY']
# End of configuration

# Assigning variables with CSV file path
addr_file = temp_directory + 'TI_ADDR.csv'
domain_file = temp_directory + 'TI_URL.csv'
hash_file = temp_directory + 'TI_HASH.csv'
dedup_file = temp_directory + 'dedup.csv'

#Function to write rows to CSV file
def writeCSV(inputfile, rows):
    with open(inputfile, 'w') as file:
        csvwriter = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        header_list = ['Indicator', 'Indicator_Type','Feed_URL','Feed_Name', 'Feed_Overlap_Count', 'Date']
        csvwriter.writerow(header_list)
        for row in rows:
            csvwriter.writerow(row)


#Function to deduplicate entried in CSV file
def dedupCSV(inputfile):
    outputfile = inputfile + ".dedup"
    #if os.path.isfile(outputfile):     # Enable this and below lines if you don't wish to accumulate old IoCs and just keep the fresh IoCs from the Threat Intel feeds
    #    os.remove(outputfile)
    
    with open(inputfile, 'r') as input_file, open(outputfile, 'a+') as out_file:
        out_file.writelines(unique_everseen(input_file))

    with open(inputfile, 'r') as input_file, open(dedup_file, 'a+') as out_file:
        out_file.writelines(unique_everseen(input_file))

    os.remove(inputfile)    # Removing non-deduplicated CSV


#Function to write parsed results to CSV files according to the type of IOC
def writeResults(results):
    ADDR_ARRAY = []
    DOMAIN_ARRAY = []
    HASH_ARRAY = []
    for row in results:
        try:
            regex = re.search("(ADDR|DOMAIN|URL|FILE_HASH)", str(row[1]))
        except:
            print "Unknown entry...Going to next one!"
            continue
        if regex.groups()[0] in "ADDR":
            ADDR_ARRAY.append(row)
        elif regex.groups()[0] in "DOMAIN":
            DOMAIN_ARRAY.append(row)
        elif regex.groups()[0] in "URL":
            DOMAIN_ARRAY.append(row)
        elif regex.groups()[0] in "FILE_HASH":
            HASH_ARRAY.append(row)

    # Writing results to CSV files
    writeCSV(addr_file, ADDR_ARRAY)
    writeCSV(domain_file, DOMAIN_ARRAY)
    writeCSV(hash_file, HASH_ARRAY)

    # Deduplicating results in CSV files
    dedupCSV(addr_file)
    dedupCSV(domain_file)
    dedupCSV(hash_file)