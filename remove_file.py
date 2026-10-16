from pathlib import Path



# Directories
output_dir = Path("resources/output")
predicted_dir = Path("resources/predicted")

# Verify directories exist
if not output_dir.exists():
    raise FileNotFoundError(f"{output_dir} does not exist")

if not predicted_dir.exists():
    raise FileNotFoundError(f"{predicted_dir} does not exist")

# Build a set of original filenames corresponding to predicted files
processed_files = set()

for pred_file in predicted_dir.glob("*_pred.csv"):
    original_name = pred_file.name.replace("_pred.csv", ".csv")
    processed_files.add(original_name)

deleted = 0

# Delete processed files from output directory
for output_file in output_dir.glob("*.csv"):
    if output_file.name in processed_files:
        print(f"Deleting: {output_file.name}")
        output_file.unlink()
        deleted += 1

print(f"\nDeleted {deleted} processed file(s).")

