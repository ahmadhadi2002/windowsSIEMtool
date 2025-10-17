import hashlib
from pathlib import Path
import pprint

def get_all_directory_files(input_path):

    data = {}
    for(current_folder, folders_in_current_folder, files_in_current_folder) in os.walk(input_path):
        data[current_folder] = {}
        data[current_folder]['Folder-List'] = folders_in_current_folder
        data[current_folder]['File-List'] = files_in_current_folder
    
    return data


def get_file_hash(file_path):

    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as file:
        for byte_block in iter(lambda: file.read(4096),b""):
            sha256_hash.update(byte_block)
        print (f"File Hash: {sha256_hash.hexdigest()}")

file_path = r"C:\Users\Jajul\Downloads\NCS_application.docx"

get_file_hash(file_path)