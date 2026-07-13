import pandas as pd
import os

from transformers import data 

print("=" * 50)
print("CICIDS2017")
print("=" * 50)
# Find whichever CSV file you have
cicids_path = "/home/rk/sentinelai/data/raw/cicids2017"
files = os.listdir(cicids_path)
print("Files found:", files)

# Read first file found
first_file = f"{cicids_path}/{files[0]}"
df = pd.read_csv(first_file)
df.columns = df.columns.str.strip()
print("Shape:", df.shape)
print("Columns:", df.columns.tolist())
print("First row:", df.iloc[0].to_dict())
print("Labels:", df["Label"].value_counts().to_dict())

print("\n" + "=" * 50)
print("RBA DATASET")
print("=" * 50)
rba_path = "/home/rk/sentinelai/data/raw/rba_dataset"

target_file2 = os.path.join(rba_path, "rba-dataset.csv")

print(f"Loading only the first 10 rows from: {target_file2}...\n")

# Use nrows=10 to load only the initial 10 rows into the DataFrame
df2 = pd.read_csv(target_file2, nrows=10)

# This will now reflect the truncated 10-row dataframe
print("Shape:", df2.shape) 

print("Columns:", df2.columns.tolist())
print("First row:", df2.iloc[0].to_dict())

print("\n" + "=" * 50)
print("PAYSIM")
print("=" * 50)
pay_path = "/home/rk/sentinelai/data/raw/paysim"
files3 = os.listdir(pay_path)
print("Files found:", files3)
df3 = pd.read_csv(f"{pay_path}/{files3[0]}")
print("Shape:", df3.shape)
print("Columns:", df3.columns.tolist())
print("First row:", df3.iloc[0].to_dict())

print("\n" + "=" * 50)
print("LOGHUB SSH")
print("=" * 50)
ssh_path = "/home/rk/sentinelai/data/raw/loghub_ssh"
files4 = os.listdir(ssh_path)
print("Files found:", files4)
with open(f"{ssh_path}/{files4[0]}", "r") as f:
    lines = f.readlines()
print("Total lines:", len(lines))
print("First 3 lines:")
for line in lines[:3]:
    print(line.strip())