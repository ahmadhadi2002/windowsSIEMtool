import win32evtlog
import win32evtlogutil
import csv
from datetime import date
from datetime import datetime
import sqlite3
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart



# Read documentation for win32evtlog
# https://timgolden.me.uk/pywin32-docs/win32evtlog.html

server = "localhost"
log_type = "Security" # Different log_types are available, like security, and application, more can be found within windows event manager
logOnEvent = {4624,4625,4634,4647,4672,4648,4776}
accEvent = {4720,4722,4723,4724,4725,4726,4732,4733,4756}
polEvent = {4719,4902,4739,4670}
securityEvent = {4618, 4649, 4719,4765,4766,4794,4897,4964,5124,1102,4692,4693,4706,4713,4716}
totalEvent = logOnEvent | accEvent | polEvent | securityEvent
curDate = date.today()
curTime = datetime.now()
timeFormat = [(curTime.hour),(curTime.minute)]
output_file = f"D:\Python_projects\windows_siem\window_event_log\{log_type}_Eventlogs_{curDate}_{timeFormat[0]}_{timeFormat[1]}.csv"
db_path = "D:\SQLite\datapacks\event-log.sqlite"
path_remove = "D:\Python_projects\windows_siem\window_event_log"
day_threshold = 7



def init_db():
    connection = sqlite3.connect(db_path)
    connection.commit()
    return connection

def compute_hash(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8', errors='ignore')).hexdigest()

def save_event_sql(connection, cur_Event):
    cur = connection.cursor()
    try:
        cur.execute("""
            INSERT INTO window_event (event_id, source, time_generated, event_type, message, msg_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            cur_Event["EventID"],
            cur_Event["Source"],
            cur_Event["TimeGenerated"],
            cur_Event["EventType"],
            cur_Event["Message"],
            compute_hash(cur_Event["Message"])
        ))
        connection.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # duplicate

def email_sender(to_email, message):
        sender_email = "ahmadhadi200228@gmail.com"
        app_password = "oqlo hnrs kgiu oqra"

        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = to_email
        msg["Subject"] = "Critical Event has occured on your device"

        msg.attach(MIMEText(message, "plain"))

        try:
            # Connect to Gmail SMTP server
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender_email, app_password)
                server.send_message(msg)
            print("Email sent successfully!")

        except Exception as e:
            print("Error sending email:", e)




# to read event logs, must have an event handler, flag read type and specifications, and the starting record value, 0 being the first 
# events = win32evtlog.ReadEventLog(handle,flags,0)

def eventChecker(eventType):

    # Opens a handler which points towards the right server for event logs
    handle = win32evtlog.OpenEventLog(server, log_type)

    # flag reading type, must determine how the logs are meant to be read
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    total= 0
    event_list = []
    critical_event = []
    connection = init_db()

    print(f"Reading {log_type} logs from {server}...\n")

    try:
        while True:
            events = win32evtlog.ReadEventLog(handle,flags,0)
            if not events:
                break
            
            for event in events:
                eventId = event.EventID
                if eventId in eventType:
                    total+=1
                    try:
                        message = win32evtlogutil.SafeFormatMessage(event, log_type)

                        cur_Event={
                        "EventID": event.EventID,
                        "Source": event.SourceName,
                        "TimeGenerated": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                        "EventType": event.EventType,
                        "Message": message.strip().replace('\r', ' ').replace('\n', ' '),
                        }

                        save_event_sql(connection,cur_Event)

                        event_list.append(cur_Event)

                        if eventId in critical_event:
                            critical_event.append(cur_Event)

                        
                    except Exception as e:
                        print("Error unbale to run SQL saving")

                    # print("-"*70)

        with open(output_file, mode="w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["EventID", "Source", "TimeGenerated", "EventType", "Message"])
            writer.writeheader()
            writer.writerows(event_list)

        if len(critical_event) > 0:
            email_sender(to_email="ahmadhadi200228@gmail.com",
                         messaget=f"Critical Event has occured on your desktop:\n" + "\n".join(critical_event))
            
        

    except Exception as e:
        print("Error:", e)
    
    print(f"\nTotal Number of Hits:{total}")

eventChecker(totalEvent)