COBOL Scanner + Small Static Program Analysis
=============================================

Summary
-------
This repository contains a single-file COBOL security scanner and a small static program analysis (SPA) tool (control/dependency extraction). The scanner will:
- Prefer an installed COBOL parser (legacylens_cobol_parser or cobol_parser) for AST-aware analysis.
- Fall back to line-oriented regex heuristics if no parser is available.
- Detect issues such as hardcoded credentials, dynamic SQL, file operations without FILE STATUS checks, string overflow risks, and unvalidated ACCEPT inputs.
- Provide a simple SPA subcommand to produce control or dependency maps (output: python/json/dot).

Files
-----
- scanner.py
  - Main script: run security scans and small SPA operations.

Prerequisites
-------------
- Python 3.7+ (Python 3.8/3.9/3.10/3.11/3.12+ recommended)
- pip

Recommended: use a virtual environment.

Quick Setup (Windows PowerShell)
-------------------------------
1. Create a venv and activate it:
   py -3 -m venv venv
   .\venv\Scripts\Activate.ps1

2. Upgrade pip (optional but recommended):
   python -m pip install --upgrade pip

3. (Optional) Install an AST parser for better analysis:
   - Preferred package names (scanner will prefer legacylens_cobol_parser, then cobol_parser):
     python -m pip install legacylens_cobol_parser
     OR
     python -m pip install cobol_parser

   If you do not install either package, the scanner will still run using built-in regex heuristics.

Quick Setup (macOS / Linux)
--------------------------
1. Create & activate venv:
   python3 -m venv venv
   source venv/bin/activate

2. Upgrade pip:
   python -m pip install --upgrade pip

3. (Optional) Install parser:
   python -m pip install legacylens_cobol_parser
   OR
   python -m pip install cobol_parser

How to run the scanner
----------------------
- Scan the current directory (recurses) with pretty output:
  python scanner.py scan . 

- Scan and use installed parser if available:
  python scanner.py scan . --use-legacylens

- Scan single file:
  python scanner.py scan myprog.cbl --use-legacylens

- Save JSON output:
  python scanner.py scan . --use-legacylens --format json > findings.json

- Find files by extension (default): .cbl, .cob, .cpy, .cobol
  Include .txt files with:
  python scanner.py scan . --include-txt

Scanner output
--------------
- Pretty output: grouped by severity with file:line, snippet, and remediation.
- JSON output: list of findings. Each finding contains:
  - rule_id, title, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO),
  - file, line, message, snippet, cwe, remediation

Tainting:
- The scanner marks variables as "tainted" when it sees ACCEPT <var>, RECEIVE ... INTO <var>, or READ ... INTO <var>. Tainted variables increase severity when used in dangerous operations (e.g., dynamic SQL).

SPA (Static Program Analysis) subcommand
----------------------------------------
The scanner includes a small SPA capability (control/dependency maps) for a single input file.

- Control flow map (detects SECTION and PERFORM):
  python scanner.py spa -t control -f json -i myprog.cbl

- Dependency (CALL) map:
  python scanner.py spa -t dep -f json -i myprog.cbl

- DOT output (render with Graphviz):
  python scanner.py spa -t control -f dot -i myprog.cbl > myprog.dot
  dot -Tsvg myprog.dot -o myprog.svg

Notes about SPA
- SPA is a lightweight, line-based heuristic. For accurate interprocedural analysis, use a full parser (LegacyLens/cobol_parser AST).

Troubleshooting
---------------
1) "Could not import legacylens_cobol_parser" or parser missing:
   - The scanner tries (in order):
     1. legacylens_cobol_parser
     2. cobol_parser
   - If neither is found it uses regex heuristics.
   - To check availability in your active Python:
     python -c "import importlib; print(importlib.util.find_spec('legacylens_cobol_parser'), importlib.util.find_spec('cobol_parser'))"

2) Module installed but scanner prints not found:
   - You may have multiple Python interpreters. Ensure you installed the parser into the same Python used to run scanner.py:
     python -m pip install cobol_parser
     python -c "import sys; print(sys.executable)"

3) Permissions / encoding:
   - Files are read with encoding='utf-8', errors='ignore'. If you need another encoding adjust scanner.py read_file.

4) False positives / negatives:
   - The built-in heuristics are conservative and line-based. For complex COBOL (copybooks, continuations, free/fixed format), install a parser (legacylens_cobol_parser/cobol_parser).

Interpreting common findings
----------------------------
- COBOL-SECRET-001 (HIGH): Hardcoded credential (MOVE/VALUE of a literal into a variable with a credential-like name). Remediation: remove secrets, use secure storage.
- COBOL-SQL-001 (HIGH): Dynamic SQL detected. Remediation: parameterize queries, validate input.
- COBOL-SQL-002 (CRITICAL): Dynamic SQL using a tainted variable. Remediation: sanitize/validate input; consider prepared statements.
- COBOL-FILE-001 (MEDIUM): File OPEN without FILE STATUS check. Remediation: define FILE STATUS and check results.
- COBOL-STR-001 (MEDIUM): STRING/UNSTRING without ON OVERFLOW nearby. Remediation: add ON OVERFLOW handler.
- COBOL-INPUT-001 (LOW): ACCEPT without nearby validation. Remediation: validate inputs.

Extending or customizing the scanner
-----------------------------------
- Add/modify rules in analyze_security() in scanner.py.
- Improve normalization for specific COBOL dialects by editing normalize_lines().
- Add --exit-code flag to return non-zero for HIGH/CRITICAL findings (useful for CI).
- Replace heuristics with AST-based checks using parser AST if available from LegacyLens.

Example workflow
----------------
1. Create venv and install parser:
   py -3 -m venv venv
   .\venv\Scripts\Activate.ps1
   python -m pip install cobol_parser

2. Run scanner:
   python scanner.py scan . --use-legacylens --format json > results.json

3. Open results.json, review HIGH/CRITICAL findings and use SPA to understand call/context:
   python scanner.py spa -t control -f dot -i suspicious.cbl > suspicious.dot
   dot -Tpng suspicious.dot -o suspicious.png

Security & Privacy
------------------
- The scanner reads source files only and prints findings to stdout. If you redirect output to files be careful with sensitive contents.
- Remove any hardcoded secrets from files before sharing publicly.

License & Attribution
---------------------
- This scanner is provided "as is" for analysis and demonstration. Adapt and integrate into your processes as you see fit.
- It optionally integrates with LegacyLens/cobol_parser projects; please consult their licenses for redistribution/usage of those libraries.
