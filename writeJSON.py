""" 
Objective: This module converts deduplicated CSV file to JSON, which is then used as a source for API requests

"""
import csv
import json

# Start of Configuration
with open('config.json') as configuration:
    ti_config = json.load(configuration)
temp_directory = ti_config['TEMP_DIRECTORY']
# End of Configuration

#This function converts input CSV to JSON
def convert(csv_read, json_file):
    with open(temp_directory + csv_read, 'r') as csv_reader:
        csvreader = csv.reader(csv_reader, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        ti_dict = {}
        ti_dict['ioc_details'] = {}
        for ioc in csvreader:
            if ioc:
                ti_dict['ioc_details'].update({ioc[0]: {"ioc": ioc[0], "ioc_type": ioc[1], "feed_url": ioc[2], "feed_name": ioc[3], "feed_overlap_count": ioc[4], "date": ioc[5]}})
            else:
                break

        json_file_name = temp_directory + json_file
        with open(json_file_name, 'w+') as json_file_descriptor:
            json_file_descriptor.write(json.dumps(ti_dict, indent=4))