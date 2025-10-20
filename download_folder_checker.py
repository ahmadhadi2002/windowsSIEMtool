from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time, os

class DownloadWatcher(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"New file detected: {event.src_path}")
            # Here you can call another script, or run analysis
            os.system("D:\Python_projects\windows_siem\browserFileCheck.py")

if __name__ == "__main__":
    path = r"C:\Users\Jajul\Downloads"
    observer = Observer()
    observer.schedule(DownloadWatcher(), path, recursive=False)
    observer.start()
    print(f"[*] Watching: {path}")

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()