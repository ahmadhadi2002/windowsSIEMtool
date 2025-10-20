import os
import time
import hashlib
from pathlib import Path
from watchdog.observers import Observer
import logging
from watchdog.events import LoggingEventHandler
from watchdog.events import FileSystemEventHandler
import requests
from dotenv import load_dotenv
import sqlite3

logging_path = Path(r"D:\Python_projects\windows_siem\download_event_log\download_activity.log")
directory_path = Path(r"C:\Users\Jajul\Downloads")
db_path = "D:\SQLite\datapacks\event-log.sqlite"
load_dotenv()
# print({k: v for k, v in os.environ.items() if "API" in k})
# log_file = "D:\Python_projects\windows_siem\download_event_log\download_activity.log"

logging.basicConfig(
    level=logging.INFO,                   # Log info, warning, error levels
    format="%(asctime)s - %(message)s",   # Timestamp + message
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(logging_path),    # Output logs to file
    ]
)

def init_db():
    connection = sqlite3.connect(db_path)
    connection.commit()
    return connection


def sql_logging(connection, data):
    cur = connection.cursor()
    try:
        cur.execute("""
            INSERT INTO download_log (FileName, FilePath, Extension, TimeGenerated, Sha256Hash, State)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data["FileName"],
            data["FilePath"],
            data["Extension"],
            data["TimeGenerated"],
            data["Sha256Hash"],
            data["State"]
        ))

        connection.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # duplicate



def get_file_hash(file_path):

    assert os.path.isfile(file_path)
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as file:
        for byte_block in iter(lambda: file.read(4096),b""):
            sha256_hash.update(byte_block)
        print (f"File: {file_path}\nFile Hash: {sha256_hash.hexdigest()}")
        fileHash = sha256_hash.hexdigest()
        return fileHash

def is_temporary_file(filename):

    temp_extensions = (
                        '.crdownload','.part','.partial','.opdownload','.tmp','.temp','idm','.listing','.aria2','.patch','.manifest','.incomplete'
                        ,'.bak','.downloading','.download','.copying'
                        )
    return filename.lower().endswith(temp_extensions)


def is_file_locked(filepath):

    if not os.path.exists(filepath):
        return False
    try:
        with open(filepath, "a"):
            return False
    except OSError:
        return True
    

def is_file_stable(filepath, wait_time=10):

    if not os.path.exists(filepath):
        return False
    
    initial_size = os.path.getsize(filepath)
    time.sleep(wait_time)
    final_size = os.path.getsize(filepath)
    return initial_size == final_size 


def virusTotal_API(sha256_hash):

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    api_key = os.getenv('API_KEY')
    # print(f"API Key: {api_key}")

    headers = {
        "accept": "application/json", 
        "x-apikey": api_key
        }
    response = requests.get(url, headers=headers)
    api_data = response.json() 
    first_key = next(iter(api_data))

    if not first_key == "error":
        try: 
            analysis_stats = api_data["data"]["attributes"]["last_analysis_stats"]
            malicious_count = analysis_stats.get("malicious",0)
            suspicious_count = analysis_stats.get("suspicious",0)
            harmless_count = analysis_stats.get("harmless",0)

            # print(f"Malicious Count:{malicious_count}\nSuspicious Count: {suspicious_count}\nHarmless Count: {harmless_count}")

            if malicious_count > harmless_count or suspicious_count > harmless_count:
                
                # print("Malicious File Detected Please Remove")
                # print(f"Virus total Reponse:{response.text}")
                api_data["state"] = "Malicious"
                return api_data
                
            else:
                # print(f"Virus total Reponse:{response.text}") 
                api_data["state"] = "Harmless"
                return api_data
        except Exception as e:
            print(f"ERROR: {e}")

    else:
        # print(f"Virus total Reponse:{response.text}") 
        api_data["state"] = "no_response"
        return api_data 
    
    # Log into sql database File_date installed(varchar), filename(varchar), extension type(varchar), processing log/data(text)
    



class MyHandler(FileSystemEventHandler):

    def on_created(self, event):

        print(f"New File created: {event.src_path}")

        filepath = event.src_path
        filename = os.path.basename(filepath)
        a,extension = os.path.splitext(filename)
        # print(f"EXTENSION:{extension}")
        connection = init_db()

        if is_temporary_file(filename):
            return
        
        while not is_file_stable(filepath) or is_file_locked(filepath):
            time.sleep(2)

        if os.path.isfile(filepath):
            # print(filepath)
            # hash = "60517f898bfac156cd298fd0a45f2e06cecee232a54667213458b99dc8d80de7"
            # hash example e710e364097f309853f0d0412a819457

            
            hash = get_file_hash(filepath)
            virusTotal_Response = virusTotal_API(hash)
            sql_data_pass = {
            "FilePath": filepath,
            "FileName": filename,
            "Extension": extension,
            "TimeGenerated": time.strftime('%d/%m/%Y', time.gmtime(os.path.getmtime(filepath))),
            "Sha256Hash": hash
            }
            logging.info(f"File Hash:{hash} | Extension:{extension} | FilePath:{filepath}")

            if virusTotal_Response["state"] == "malicious":
                logging.warning(f"Malicous File Detected: {filename} | SHA256: {hash}")
                sql_data_pass["State"] == "malicious"
                if sql_logging(connection, sql_data_pass):
                    print("SQL LOGGING COMPLETE")
                    print("-"*70)
                    logging.info(f"END LOG")

                
            elif virusTotal_Response["state"] == "harmless":
                logging.info(f"File: {filename} checked and safe")
                sql_data_pass["State"] == "harmless"
                if sql_logging(connection, sql_data_pass):
                    print("SQL LOGGING COMPLETE")
                    print("-"*70)
                    logging.info(f"END LOG")
            
            elif virusTotal_Response["state"] == "no_response":
                logging.info(f"File: {filename} No data retrieval from VirusTotal")
                sql_data_pass["State"] = "no_response"
                if sql_logging(connection, sql_data_pass):
                    print("SQL LOGGING COMPLETE")
                    print("-"*70)
                    logging.info(f"END LOG")
                


log_event_handler = LoggingEventHandler()
observer = Observer()
event_handler = MyHandler()
observer.schedule(log_event_handler,logging_path,recursive=True)
# observer.schedule(log_event_handler, directory_path, recursive=True)
observer.schedule(event_handler,directory_path, recursive=True)
observer.start()

print(f"[*] Watching directory: {directory_path}")
try:
    while True:
        time.sleep(5)
except KeyboardInterrupt:
    observer.stop()
observer.join()