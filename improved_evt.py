import os
from datetime import datetime
from Evtx.Evtx import File as EvtxFile
from Evtx.Views import evtx_file_xml_view

evtx_folder = r"C:\Users\profo\Downloads\Logs\Logs"   
output_txt_folder = r"C:\Users\profo\Desktop\EDR\StructuredTXT_Classic"

os.makedirs(output_txt_folder, exist_ok=True)

print("Using classic python-evtx parser for better Security timestamp extraction...\n")

for filename in os.listdir(evtx_folder):
    if not filename.lower().endswith('.evtx'):
        continue
    if "security" not in filename.lower():
        print(f"Skipping (not Security): {filename}")
        continue

    evtx_path = os.path.join(evtx_folder, filename)
    txt_path = os.path.join(output_txt_folder, filename.replace('.evtx', '_classic.txt'))

    print(f"Processing: {filename}")

    try:
        with open(evtx_path, 'rb') as f:
            evtx = EvtxFile(f)
            with open(txt_path, 'w', encoding='utf-8') as txt_file:
                txt_file.write(f"=== EVTX File: {filename} (Classic Parser) ===\n")
                txt_file.write(f"Processed: {datetime.now()}\n\n")

                for record in evtx.records():
                    xml_view = evtx_file_xml_view(record)
                    timestamp = record.timestamp()   # This often works better on Security

                    txt_file.write("--- Record ---\n")
                    txt_file.write(f"TimeCreated: {timestamp}\n")
                    txt_file.write(f"EventID: {record.event_id()}\n")
                    txt_file.write(f"Level: {record.level()}\n")
                    txt_file.write(f"Provider: {record.provider_name()}\n")
                    txt_file.write(f"Message: {xml_view}\n")
                    txt_file.write("="*80 + "\n\n")

        print(f"    Saved classic TXT: {os.path.basename(txt_path)}")

    except Exception as e:
        print(f"    Error: {e}")

print("\nClassic parser finished. Check the new _classic.txt file for timestamps.")