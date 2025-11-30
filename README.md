# RhombixTechnologies_Task3
Bug Bounty Debugger


# Rhombix Debugger (Intern Project)
Advanced Python static-code vulnerability scanner with GUI.

## Features
- AST-based detection: eval/exec, use of subprocess with shell=True, os.system, pickle use, insecure requests (verify=False), hardcoded secrets, SQL concatenation patterns, weak hashes (md5).
- GUI (Tkinter): choose file/folder, run scan, view results, export JSON/HTML report, view fix suggestions.
- Sample vulnerable file included.

## Run (Linux/Windows)
1. Make folder `RhombixTechnologies_Tasks` and add files from repo.
2. Create venv (recommended) and install:
