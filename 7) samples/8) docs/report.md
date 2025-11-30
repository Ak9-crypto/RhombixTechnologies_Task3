# Rhombix Debugger — Project Report

## Overview
This project implements an advanced Python static vulnerability scanner with a graphical interface. The scanner uses AST-based checks and regex heuristics to detect common insecure coding patterns.

## Design
- scanner.py : AST visitor to detect eval/exec, subprocess shell usage, pickle imports, insecure requests, hardcoded secrets, etc.
- gui.py : Tkinter GUI to select path, run scan, view and export results.
- utils.py : export JSON and HTML report (Jinja2 template).

## Test
Run `python3 main.py` and open the GUI. Scan the included `samples/vulnerable_example.py` to see flagged issues.

## Remediation & Extension Ideas
- Add language support for JS (use tree-sitter).
- Add CI integration (GitHub Action) to run scan on PRs.
- Add severity scoring and CWE mapping.
