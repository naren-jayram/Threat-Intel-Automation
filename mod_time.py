'''
Objective: To pick only latest Threat Intel Feeds

Logic:
   1.NEW_FILE_LIST = []
   2.Read 'last_modification.csv' and create a dictionary {"filename":"modified_time"}
   3.Read modification time from File System directory and update dictionary for each filename, append NEW_FILE_LIST for new entries
   4.Write 'last_modification.csv' by iterating through dictionary
'''

import os
import csv
import json

# Configuration
with open('config.json')as configuration:
    ti_config = json.load(configuration)
feed_directory = ti_config['FEED_DIRECTORY']
temp_directory = ti_config['TEMP_DIRECTORY']
# End of Configuration

# Start of variables
NEW_FILE_LIST = []
FS_LOG_DICT = {}
mod_time_list = []
last_mod_csv_file = temp_directory + 'last_modification.csv'
# End of variables


def new_ti_feed_files():
    fs_files_list = os.listdir(feed_directory)
    if os.path.isfile('last_mod_csv_file'):
        # Build a dictionary from CSV file
        with open(last_mod_csv_file, "r+") as csvfs:
            fs_list = csv.reader(csvfs)
            for row in fs_list:
                FS_LOG_DICT[row[0]] = row[1]    # {"filename":"modified_time"}

        
        # Use Case:  File deleted from the directory but, file name exists in CSV file, last_modification.csv
        deleted_files = list(set(FS_LOG_DICT.keys()) - set(fs_files_list))
        if deleted_files:
            print("These files are no more existing in the filesystem: ", deleted_files)
            for filename in deleted_files:                          # Delete the key [filename] from Dictionary
                del FS_LOG_DICT[filename]

        for filename in fs_files_list:
            try:
                stat = os.stat("%s/%s"%(feed_directory, filename))        #pull the file stats from feed_directory
                print("%s -------->%s" %(filename,stat.st_mtime))

                # Use Case: New file found
                if filename not in FS_LOG_DICT:                     
                    NEW_FILE_LIST.append(filename)                  # To pick the new files 
                    FS_LOG_DICT[filename] = stat.st_mtime           # Update the dictionary with new file stats {"filename":"modified_time"}
                else:
                    # Use Case: If modification time of the existing file remains same
                    if(stat.st_mtime == float(FS_LOG_DICT[filename])):
                        print ("Observed same modification time! for %s" % filename)
                    
                    # Use Case: If modification time of the existing file has changed
                    else:
                        NEW_FILE_LIST.append(filename)          # To pick the files that has a new modification time
                        FS_LOG_DICT[filename] = stat.st_mtime   # Update the latest modification time to dictionary, FS_LOG_DICT

            except Exception as ErrMsg:
                print(ErrMsg)

        #print(FS_LOG_DICT)

        # Write dictionary(FS_LOG_DICT) contents to csv file 'last_modification.csv' for future reference
        with open(last_mod_csv_file, 'w') as csvfile:    
            for f_name, f_mtime in FS_LOG_DICT.items():
                write_descriptor = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL )
                write_descriptor.writerow([f_name, f_mtime])

        if NEW_FILE_LIST:
            #print("List of NEW FILES FOUND: ", NEW_FILE_LIST)
            return NEW_FILE_LIST
    else:
        print("Sorry! did not find <last_modification.csv> file")
        for filename in fs_files_list:
            stat = os.stat("%s/%s"%(feed_directory, filename))        #pull the file stats from feed_directory
            print("%s -------->%s" %(filename,stat.st_mtime))
            mod_time_list.append([filename,stat.st_mtime])
            NEW_FILE_LIST.append(filename)

        with open(last_mod_csv_file, 'w+') as csvfile:    
            for mod_details in mod_time_list:
                write_descriptor = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL )
                write_descriptor.writerow(mod_details)

        return NEW_FILE_LIST

if __name__ == '__main__':
  func = new_ti_feed_files()

