
evtx_folder = r"C:\Users\profo\Downloads\Logs\Logs"   
output_txt_folder = r"C:\Users\profo\Downloads\Stuctured"         
final_output_folder = r"C:\Users\profo\Downloads\output"    

import os
import json
import pandas as pd
from datetime import datetime
from pathlib import Path
from evtx import PyEvtxParser



os.makedirs(output_txt_folder, exist_ok=True)
os.makedirs(final_output_folder, exist_ok=True)

# Filter for relevant files only (customize these keywords for EMR incidents)
RELEVANT_KEYWORDS = [
    "security", "system", "application", "setup", "device", "userpnp",
    "service", "audit", "logon", "access", "error", "microsoft-windows"
]

def is_relevant_evtx(filename: str) -> bool:
    fname = filename.lower()
    return any(kw in fname for kw in RELEVANT_KEYWORDS)

# ====================== INCIDENT CLASSIFICATION ======================
def classify_incident(row):
    msg = str(row.get('Message', '')).lower()
    event_id = str(row.get('EventID', ''))
    level = str(row.get('Level', '')).lower()
    provider = str(row.get('Provider', '')).lower()

    if event_id in ['4624', '4625'] or 'logon' in msg:
        return "Authentication_Failure" if event_id == '4625' or 'failure' in msg else "Successful_Login"
    elif 'error' in level or 'critical' in level or event_id in ['1000', '1001', '1002']:
        return "Application_Error"
    elif any(x in provider for x in ['userpnp', 'device']) or any(x in msg for x in ['device', 'usb', 'install']):
        return "Device_Installation"
    elif any(x in msg for x in ['service start', 'service stop', '7036', '7045', 'new service']):
        return "Service_Change"
    elif any(x in msg for x in ['access denied', 'unauthorized', 'permission denied']):
        return "Access_Control_Violation"
    elif any(x in msg for x in ['network', 'wifi', 'connectivity']):
        return "Network_Connectivity"
    else:
        return "Other_Non_Incident"

# ====================== MAIN PROCESSING ======================
print("Starting .evtx parsing...\n")

all_events = []

for filename in os.listdir(evtx_folder):
    if not filename.lower().endswith('.evtx'):
        continue
    if not is_relevant_evtx(filename):
        print(f"Skipping (not relevant): {filename}")
        continue

    evtx_path = os.path.join(evtx_folder, filename)
    txt_path = os.path.join(output_txt_folder, filename.replace('.evtx', '.txt'))

    print(f" Processing: {filename}")

    try:
        parser = PyEvtxParser(evtx_path)

        with open(txt_path, 'w', encoding='utf-8') as txt_file:
            txt_file.write(f"=== EVTX File: {filename} ===\n")
            txt_file.write(f"Processed: {datetime.now()}\n\n")

            for record in parser.records_json():
                event = json.loads(record['data'])['Event']
                
                # Extract key fields
                system = event.get('System', {})
                time_created = system.get('TimeCreated', {}).get('@SystemTime')
                event_id = system.get('EventID')
                level = system.get('Level')
                provider = system.get('Provider', {}).get('@Name')
                
                # Get full message (EventData or RenderingInfo)
                message = ""
                if 'EventData' in event:
                    message = str(event['EventData'])
                elif 'RenderingInfo' in event and 'Message' in event['RenderingInfo']:
                    message = event['RenderingInfo']['Message']

                # Write structured TXT
                txt_file.write(f"--- Record ---\n")
                txt_file.write(f"TimeCreated: {time_created}\n")
                txt_file.write(f"EventID: {event_id}\n")
                txt_file.write(f"Level: {level}\n")
                txt_file.write(f"Provider: {provider}\n")
                txt_file.write(f"Message: {message}\n")
                txt_file.write("=" * 80 + "\n\n")

                # Collect for DataFrame
                all_events.append({
                    'TimeCreated': time_created,
                    'EventID': event_id,
                    'Level': level,
                    'Provider': provider,
                    'Message': message,
                    'Log_Source_File': filename,
                    'RecordID': record.get('record_id')
                })

    except Exception as e:
        print(f" Error processing {filename}: {e}")
        continue

# ====================== CREATE DATAFRAME & SAVE ======================
if not all_events:
    print("  No events extracted. Check folder path or file permissions.")
else:
    df = pd.DataFrame(all_events)
    df = df.fillna('')                    # Handle empty cells gracefully
    df = df[df['TimeCreated'] != '']      # Remove completely empty rows
    
    df['Incident_Type'] = df.apply(classify_incident, axis=1)

    # Master labelled CSV
    master_path = os.path.join(final_output_folder, "MASTER_windows_events_labelled.csv")
    df.to_csv(master_path, index=False, encoding='utf-8')
    
    # Separate CSVs per incident type
    for inc_type in df['Incident_Type'].unique():
        subset = df[df['Incident_Type'] == inc_type]
        if not subset.empty:
            clean_name = inc_type.lower().replace(' ', '_').replace('/', '_')
            inc_path = os.path.join(final_output_folder, f"incident_{clean_name}.csv")
            subset.to_csv(inc_path, index=False, encoding='utf-8')

    print(f"\n Processing completed successfully!")
    print(f"   Total events extracted: {len(df):,}")
    print(f"   Structured .txt files → {output_txt_folder}")
    print(f"   Final CSVs → {final_output_folder}")
    print(f"   Master file: MASTER_windows_events_labelled.csv")
    print(f"\nIncident Types found: {sorted(df['Incident_Type'].unique())}")

print("\nYou can now use the MASTER CSV for model training.")
