from datetime import datetime, timedelta
import datetime
import os
import csv
import json

#Configuration
with open('config.json')as configuration:
    ti_config = json.load(configuration)
    retention_days = ti_config['IOC_RETENTION_DAYS']
    temp_directory = ti_config['TEMP_DIRECTORY']
#End of Configuration

today_date_time = datetime.datetime.now()
today_date = today_date_time.date()

retention_date_time = datetime.datetime.now() - timedelta(days=int(retention_days))
retention_date = retention_date_time.date()


# Injecting headers to temporary csv files
def csv_header(csv_file_name):
    with open(temp_directory + csv_file_name, 'w+') as ti_writer:
        ti_csvwriter = csv.writer(ti_writer,delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        header_list = ['Indicator', 'Indicator_Type','Feed_URL','Feed_Name', 'Feed_Overlap_Count', 'Date']
        ti_csvwriter.writerow(header_list)


# Reads IoC details that satisfies the retention period from TI_ADDR.csv.dedup, TI_URL.csv.dedup, TI_HASH.csv.dedup and writes it to TI_ADDR_TEMP.csv, TI_URL_TEMP.csv and TI_HASH_TEMP.csv respectively.
def ioc_retention(original_file,temp_file):
    if os.path.isfile(temp_directory + original_file):  
        with open(temp_directory + original_file, 'r') as ti_reader:
            ti_csvreader = csv.reader(ti_reader,delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
            for ioc in ti_csvreader:
                try:
                    ioc_date_str = ioc[5]                                                                   # fetches date field from csv file
                    type_converted_ioc_date_time = datetime.datetime.strptime(ioc_date_str, "%Y-%m-%d")     # Converts string type date to date format
                    type_converted_ioc_date = type_converted_ioc_date_time.date()                           # Fetches only date and not time
                    if type_converted_ioc_date >= retention_date:                                           # If date field from csv greater than retention_date
                        with open(temp_directory + temp_file, 'a') as ti_writer:
                            ti_csvwriter = csv.writer(ti_writer,delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
                            ti_csvwriter.writerow(ioc)
                except:
                    continue

    else:
        print "No file found!", original_file



def cleanup():

    # Taking backup of existing TI_ADDR.csv, TI_URL.csv and TI_HASH.csv; Renaming TI_ADDR_TEMP.csv, TI_URL_TEMP.csv, TI_HASH_TEMP.csv as TI_ADDR.csv.dedup, TI_URL.csv.dedup and TI_HASH.csv.dedup respectively.
    # New TI_ADDR.csv, TI_URL.csv and TI_HASH.csv files will only contain IoC details that matches retention criterion
    for file_name in os.listdir(temp_directory):
        if file_name in "TI_ADDR.csv.dedup":
            file_backup_name = "TI_ADDR" + "_" + "BKP" + "_" + str(today_date) + ".csv"                       # TI_ADDR_BKP_today-date.csv
            os.rename(temp_directory+file_name, temp_directory+file_backup_name)                               # Backing up the existing file
            os.rename(temp_directory+'TI_ADDR_TEMP.csv', temp_directory + file_name)                           # Changing the name of TI_ADDR_TEMP.csv to TI_ADDR.csv

        elif file_name in "TI_URL.csv.dedup":
            file_backup_name = "TI_URL" + "_" + "BKP" + "_" + str(today_date) + ".csv"
            os.rename(temp_directory+file_name, temp_directory+file_backup_name)
            os.rename(temp_directory+'TI_URL_TEMP.csv', temp_directory+file_name)

        elif file_name in "TI_HASH.csv.dedup":
            file_backup_name = "TI_HASH" + "_" + "BKP" + "_" + str(today_date) + ".csv"
            os.rename(temp_directory+file_name, temp_directory+file_backup_name)
            os.rename(temp_directory+'TI_HASH_TEMP.csv', temp_directory+file_name)

csv_header('TI_ADDR_TEMP.csv')
csv_header('TI_URL_TEMP.csv')
csv_header('TI_HASH_TEMP.csv')
#csv_header('TI_OTHERS_TEMP.csv')

ioc_retention('TI_ADDR.csv.dedup', 'TI_ADDR_TEMP.csv')
ioc_retention('TI_URL.csv.dedup', 'TI_URL_TEMP.csv')
ioc_retention('TI_HASH.csv.dedup', 'TI_HASH_TEMP.csv')
cleanup()
