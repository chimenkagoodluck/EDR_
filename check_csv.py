import os
import pandas as pd

def scan_csv_files(root_folder="."):
   
    csv_files = []

    
    for foldername, subfolders, filenames in os.walk(root_folder):
        for file in filenames:
            if file.lower().endswith(".csv"):
                full_path = os.path.join(foldername, file)
                csv_files.append(full_path)

    if not csv_files:
        print("No CSV files found.")
        return

    print(f"Found {len(csv_files)} CSV file(s):\n")

    for file_path in csv_files:
        try:
            
            df = pd.read_csv(file_path, nrows=5)  # Read first 5 rows only
            print(f"[OK] {file_path}")
            print(f"     Rows Preview: {len(df)} row(s) loaded")
            print(f"     Columns: {list(df.columns)}\n")

        except Exception as e:
            print(f"[ERROR] {file_path}")
            print(f"        Reason: {e}\n")


if __name__ == "__main__":
    current_folder = os.getcwd()
    print(f"Scanning project folder: {current_folder}\n")
    scan_csv_files(current_folder)