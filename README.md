# PII Detection and Anonymization Script

<img width="800" height="400" alt="image-346" src="https://github.com/user-attachments/assets/5378503f-d43f-49d4-ae2e-3a4c84b03a52" />

This script is designed to detect and anonymize Personally Identifiable Information (PII) in CSV files with JSON data.

## File Information

- **Python Script**: `detector_pratham_verma.py`
- **Input File**: `iscp_pii_dataset.csv`
- **Output File**: `detector_output_pratham_verma.csv`

## Execution Command

```bash
python3 detector_pratham_verma.py iscp_pii_dataset.csv
```

Example output:
```
Starting PII detection for 'iscp_pii_dataset.csv'...
Processing complete. Output saved to 'detector_output_pratham_verma.csv'
```

## Features

The script detects and anonymizes various types of PII:

### Standalone PII Detection
- Phone numbers (10 digits)
- Aadhar numbers (12 digits with optional spaces)
- Passport numbers (specific format)
- UPI IDs

### Combinatorial PII Detection
- Email addresses
- Full names
- Physical addresses
- IP addresses
- Device IDs

## Anonymization Methods

1. **Phone Numbers**: `1234567890` → `12XXXXXX90`
2. **Aadhar**: `1234 5678 9012` → `XXXXXXXX9012`
3. **Passport**: `A1234567` → `AXXXXXX7`
4. **Names**: `John Doe` → `JXXX DXX`
5. **Email**: `john.doe@example.com` → `jXXXe@example.com`
6. **UPI ID**: Replaced with `[REDACTED_UPI]`
7. **Address**: Replaced with `[REDACTED_ADDRESS]`
8. **Device/IP**: Replaced with `[REDACTED_IDENTIFIER]`

## Input Format

The input CSV file must contain:
- `record_id`: Unique identifier for each record
- `data_json`: JSON string containing the data to process

## Output Format

The script generates a CSV with:
- `record_id`: Original record identifier
- `redacted_data_json`: JSON with anonymized data
- `is_pii`: Boolean flag indicating PII detection

## Error Handling

- Gracefully handles malformed JSON
- Reports file access errors
- Maintains data structure while anonymizing

## Dependencies

- Python 3.x
- Standard library modules only:
  - `re`
  - `json`
  - `csv`
  - `argparse`
  - `typing`

## Usage Example

```bash
# Basic usage with default output filename
python3 detector_pratham_verma.py iscp_pii_dataset.csv

# Specify custom output file
python3 detector_pratham_verma.py iscp_pii_dataset.csv -o custom_output.csv
```

## Project Structure
```
.
├── detector_pratham_verma.py     # Main script
├── iscp_pii_dataset.csv         # Input data file
└── detector_output_pratham_verma.csv  # Generated output
```

## Note

This is a specialized PII detection and anonymization tool designed for processing CSV files containing JSON data with potential personally identifiable information.
