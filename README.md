# Sophos Exclusions

> Use Sophos Central API credential to pull lists for exclusions and allowed apps.

---

## Features

- Sophos Central has no native way to export exclusions via portal settings which can easily contain hundreds of entries
  - This app leverages the API to accomplish this instead
- All input fields are stripped of leading and trailing spaces for easier pasting
- Can specify output folder, but it defaults to user's home directory
- Can prepend the output file names using the "Customer Name" field, but this is optional 
  - Note that subsequent runs will overwrite if the customer name matches (or is left blank) and files of the same name already exist in the output folder
- Lighter cmd run option coming soon

---

## Requirements

### Executable
- OS: Windows 10 or later

### (Not yet released cmd version)
- Python 3.11+
- OS: Windows / macOS / Linux

---

## Installation

### Option 1: 

- Coming soon

### Option 2:

- Coming Soon