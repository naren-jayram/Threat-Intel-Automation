""" 
Objective: This is a core application module for Threat Intel Automation. It provides application handlers as well as conducts feeds auto-refresh every n minutes.
"""
from flask import Flask, jsonify
from flask import request
import json
import threading
import commands

#Custom modules
import parseTI
import writeJSON

# Start of Configuration
with open('config.json') as configuration:
    ti_config = json.load(configuration)
temp_directory = ti_config['TEMP_DIRECTORY']
ti_addr_dict_file = temp_directory + "TI_ADDR.json"  
ti_url_dict_file = temp_directory + "TI_URL.json"  
ti_hash_dict_file = temp_directory + "TI_HASH.json"  
# ti_others_dict_obj = temp_directory + "TI_Others.json"
# End of Configuration

# Defining TI Dictionaries
ti_addr_dict = {}
ti_url_dict = {}
ti_hash_dict = {}


# MAIN APPLICATION CODE
def create_app():

    application = Flask(__name__)

    def handler():
        threading.Timer(3600.0, handler).start()        # Refreshes/ Runs every 1 hour
        #print "Getting latest feeds..."
        #print "######################################################\n"
        #cmd = "critical-stack-intel pull"
        #pull_feed = commands.getoutput(cmd)
        print "Parsing Threat Intel feeds and removing duplicates if there are any new feeds..."
        print "######################################################\n"
        # Parsing feeds and converting to JSON
        parseTI.parse()
        writeJSON.convert('TI_ADDR.csv.dedup', 'TI_ADDR.json')
        writeJSON.convert('TI_URL.csv.dedup', 'TI_URL.json')
        writeJSON.convert('TI_HASH.csv.dedup', 'TI_HASH.json')
        
        # Refreshing data
        print "Refreshing IoCs..."
        print "#####################################################\n"
        refresh_data()
        print "All good! Currently running threads:\n "
        for t in threading.enumerate():
            print t


    # Function to refresh files after Threat Intel Feeds were updated
    def refresh_data():
        global ti_addr_dict
        global ti_url_dict
        global ti_hash_dict

        ti_addr_dict.clear()
        ti_url_dict.clear()
        ti_hash_dict.clear()

        with open(ti_addr_dict_file, "r") as ti_addr_json:
            ti_addr_dict = json.load(ti_addr_json)

        with open(ti_url_dict_file, "r") as ti_url_json:
            ti_url_dict = json.load(ti_url_json)

        with open(ti_hash_dict_file, "r") as ti_hash_json:
            ti_hash_dict = json.load(ti_hash_json)


    @application.route('/addr', methods=['GET'])
    def get_addr():
        query_ioc = request.args.get('addr')
        return jsonify({"ioc_details": ti_addr_dict['ioc_details'].get(query_ioc, {"error": "No records found"})})

    @application.route('/url', methods=['GET'])
    def get_url():
        query_ioc = request.args.get('url')
        return jsonify({"ioc_details": ti_url_dict['ioc_details'].get(query_ioc, {"error": "No records found"})})

    @application.route('/hash', methods=['GET'])
    def get_hash():
        query_ioc = request.args.get('hash')
        return jsonify({"ioc_details": ti_hash_dict['ioc_details'].get(query_ioc, {"error": "No records found"})})


    handler()
    return application


application = create_app()


