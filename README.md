```markdown
# Hashing Practice — MD5 vs SHA-1 vs SHA-256 (No Crypto Libraries)

This project demonstrates how hashing algorithms ensure file integrity and detect tampering.  
It compares MD5, SHA-1, and SHA-256 hash values for files and shows how a single-bit change alters the hashes.

All three algorithms are implemented manually in Python without using cryptographic libraries (`hashlib`, `Crypto`, etc.).  
Small helper libraries are used only for CLI interaction, progress display, and table formatting.

---

## Project files

| File | Description |
|------|-------------|
| `main.py` | Main script. Handles CLI arguments, tampering demo, and table display. |
| `hashing.py` | Manual implementations of MD5, SHA-1, and SHA-256. |
| `utils.py` | File reading, tampering, and table-rendering utilities. |
| `requirements.txt` | Lists helper libraries for CLI and output formatting. |
| `README.md` | This documentation file. |

---
### (Optional) Create a virtual environment

```bash
python3 -m venv .venv
```

Activate it:

Windows:
```bash
.venv\Scripts\activate
```

macOS / Linux:
```bash
source .venv/bin/activate
```

### Install required libraries

```bash
pip install -r requirements.txt
```

Example `requirements.txt`:
```
typer>=0.12
tabulate>=0.9
tqdm>=4.66
```

These are not cryptographic libraries; they are used for CLI, progress bar, and table display.

---

## Running the program

1. Hash all files in a folder:

```
python3 main.py compare samples/
```

2. Hash multiple files or folders:

```
python3 main.py compare samples/ another_folder/ somefile.txt
```

3. Demonstrate tampering (flip one bit):

```
python3 main.py compare samples/ --tamper samples/file1.txt
```
---

## Key parts of the code (one-line notes)

| File         | Logic                                          | Explanation                                      |
| ------------ | ---------------------------------------------- | ------------------------------------------------ |
| `main.py`    | Uses `typer` for commands                      | Makes the program easy to run from the terminal  |
| `main.py`    | Calls `md5_hex()`, `sha1_hex()`, `sha256_hex()`| Computes hashes with manual implementations      |
| `main.py`    | Displays table via `tabulate`                  | Shows results in a readable format               |
| `utils.py`   | `iter_files()`                                 | Finds files in given folders                     |
| `utils.py`   | `make_tampered_copy()`                         | Creates a copy of a file with one flipped bit    |
| `utils.py`   | `render_table()`                               | Prints results using `tabulate` or ASCII fallback|
| `hashing.py` | MD5 logic                                      | Processes 512-bit blocks and bit rotations      |
| `hashing.py` | SHA-1 logic                                    | Uses message expansion and 80 rounds             |
| `hashing.py` | SHA-256 logic                                  | Uses 64 constants and bitwise operations         |

---

## Summary

This project provides manual implementations of MD5, SHA-1, and SHA-256 and shows how a small change in a file produces large differences in hash outputs. Use the provided commands to run the demo and verify the results.
```
