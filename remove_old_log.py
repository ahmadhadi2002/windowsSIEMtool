import os
import time
from pathlib import Path

path_remove = r"D:\Python_projects\windows_siem\window_event_log"

day_threshold = 7


def log_date_checker(path_remove, day_threshold):
    
    folder_path = Path(path_remove)
    current_time = time.time()

    for file in folder_path.iterdir():
        if file.is_file():
            creation_time = os.path.getctime(file)
            file_age_days = (current_time - creation_time) / (24*3600)
            print(f"File Age: {file_age_days}")

            if file_age_days > day_threshold:
                try:
                    os.remove(file)
                except Exception as e:
                    print(f"Error:{e}")

log_date_checker(path_remove, day_threshold)