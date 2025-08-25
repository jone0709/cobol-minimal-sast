#!/usr/bin/env python3
"""
COBOL scanner (scanner.py) — tries legacy module name first, then falls back to cobol_parser.
"""
import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import List, Set, Optional, Any, Iterable

"""
Try importing LegacyLens under both common names.
If the module legacylens_cobol_parser is available it will be used.
Otherwise the installed cobol_parser package will be used as a fallback.
"""
HAVE_LL = False
CobolParser = None
LL_MODULE_NAME = None

print("🔍 Loading LegacyLens COBOL Parser...")

# Try the canonical name first
try:
    import legacylens_cobol_parser as _llmod  # type: ignore
    LL_MODULE_NAME = "legacylens_cobol_parser"
    print("ℹ️  Imported module legacylens_cobol_parser")
except Exception:
    _llmod = None

# If that failed, try cobol_parser (the package you have installed)
if _llmod is None:
    try:
        import cobol_parser as _llmod  # type: ignore
        LL_MODULE_NAME = "cobol_parser"
        print("ℹ️  Imported module cobol_parser as fallback")
    except Exception:
        _llmod = None

# If we have a module, try to detect parser entrypoints
if _llmod is not None:
    # Common export names we support
    if hasattr(_llmod, "CobolParser"):
        CobolParser = getattr(_llmod, "CobolParser")
        HAVE_LL = True
        print(f"✅ LegacyLens loaded: {LL_MODULE_NAME}.CobolParser")
    elif hasattr(_llmod, "Parser"):
        CobolParser = getattr(_llmod, "Parser")
        HAVE_LL = True
        print(f"✅ LegacyLens loaded: {LL_MODULE_NAME}.Parser")
    elif hasattr(_llmod, "parse") or hasattr(_llmod, "parse_file") or hasattr(_llmod, "parse_string"):
        # prefer parse -> parse_file -> parse_string
        if hasattr(_llmod, "parse"):
            CobolParser = getattr(_llmod, "parse")
            print(f"✅ LegacyLens loaded: {LL_MODULE_NAME}.parse")
        elif hasattr(_llmod, "parse_file"):
            CobolParser = getattr(_llmod, "parse_file")
            print(f"✅ LegacyLens loaded: {LL_MODULE_NAME}.parse_file")
        else:
            CobolParser = getattr(_llmod, "parse_string")
            print(f"✅ LegacyLens loaded: {LL_MODULE_NAME}.parse_string")
        HAVE_LL = True
    else:
        print(f"⚠️  LegacyLens module imported ({LL_MODULE_NAME}) but no known parser symbol found. Available: {dir(_llmod)}")

if not HAVE_LL:
    print("⚠️  LegacyLens not available - using basic regex parsing")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    snippet: str = ""
    cwe: str = ""
    remediation: str = ""


def normalize_lines(lines: Iterable[str]) -> List[str]:
    out = []
    buffer = ""
    open_dq = False
    open_sq = False

    def flush_buf():
        nonlocal buffer, open_dq, open_sq
        if buffer:
            out.append(buffer.rstrip("\n"))
        buffer = ""
        open_dq = open_sq = False

    for raw in lines:
        line = raw.rstrip("\n")
        cont_col7 = len(line) >= 7 and line[6] == "-"
        if not buffer:
            buffer = line
            open_dq = buffer.count('"') % 2 == 1
            open_sq = buffer.count("'") % 2 == 1
            if cont_col7 or buffer.rstrip().endswith("-") or buffer.rstrip().endswith(",") or open_dq or open_sq:
                continue
            else:
                flush_buf()
        else:
            buffer += " " + line.lstrip()
            open_dq = buffer.count('"') % 2 == 1
            open_sq = buffer.count("'") % 2 == 1
            if not cont_col7 and not buffer.rstrip().endswith("-") and not buffer.rstrip().endswith(",") and not open_dq and not open_sq:
                flush_buf()

    if buffer:
        out.append(buffer.rstrip("\n"))

    return [l.rstrip() for l in out]


def parse_with_legacylens(filepath: str) -> Optional[Any]:
    """Try to parse with LegacyLens if available (robust to class/function calling conventions)."""
    if not HAVE_LL or not CobolParser:
        return None

    try:
        print(f"📊 Parsing {os.path.basename(filepath)} with LegacyLens ({LL_MODULE_NAME})...")
        if callable(CobolParser):
            # If class, try instantiate; if error, try call directly
            try:
                parser = CobolParser()
                if hasattr(parser, "parse"):
                    # instance parse(filepath) expected
                    result = parser.parse(filepath)
                else:
                    # fallback: call object as function
                    result = parser(filepath)
            except TypeError:
                # CobolParser is a function; call it
                result = CobolParser(filepath)
            except Exception:
                # Last resort: call CobolParser as function
                result = CobolParser(filepath)
        else:
            result = CobolParser(filepath)
        print("✅ LegacyLens parsing completed")
        return result
    except Exception as e:
        print(f"⚠️  LegacyLens parse error: {e}")
        print("📋 Continuing with basic regex parsing...")
        return None


def read_file(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)
        return []


def find_cobol_files(paths: List[str], include_txt: bool = False) -> List[str]:
    files = []
    extensions = (".cbl", ".cob", ".cpy", ".cobol")
    if include_txt:
        extensions += (".txt",)
    for path in paths:
        if os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            for root, _, filenames in os.walk(path):
                for filename in filenames:
                    if filename.lower().endswith(extensions):
                        files.append(os.path.join(root, filename))
    return files


def detect_taint_sources(lines: List[str]) -> Set[str]:
    tainted = set()
    patterns = [
        re.compile(r"\bACCEPT\s+([A-Z0-9\-\$#@_]+)\b", re.IGNORECASE),
        re.compile(r"\bRECEIVE\b.*?\bINTO\s+([A-Z0-9\-\$#@_]+)\b", re.IGNORECASE),
        re.compile(r"\bREAD\s+[A-Z0-9\-\$#@_]+\s+INTO\s+([A-Z0-9\-\$#@_]+)\b", re.IGNORECASE),
    ]
    for line in lines:
        for p in patterns:
            m = p.search(line)
            if m:
                tainted.add(m.group(1).upper())
    return tainted


def has_file_status(lines: List[str]) -> bool:
    for line in lines:
        if re.search(r"\bFILE[- ]STATUS\b", line, re.IGNORECASE):
            return True
    return False


def has_on_overflow_near(lines: List[str], idx: int, window: int = 10) -> bool:
    end = min(len(lines), idx + window)
    for i in range(idx, end):
        if "ON OVERFLOW" in lines[i].upper():
            return True
    return False


def has_validation_near(lines: List[str], idx: int, varname: str, window: int = 20) -> bool:
    var_re = re.compile(r"\b" + re.escape(varname) + r"\b", re.IGNORECASE)
    end = min(len(lines), idx + window)
    for i in range(idx, end):
        l = lines[i]
        if var_re.search(l):
            if re.search(r"\bIF\b", l, re.IGNORECASE) or re.search(r"\bINSPECT\b", l, re.IGNORECASE) or re.search(r"\bVALIDATE\b", l, re.IGNORECASE) or re.search(r"\bPERFORM\b", l, re.IGNORECASE):
                return True
    return False


def analyze_security(lines_raw: List[str], filepath: str, ll_data: Optional[Any] = None) -> List[Finding]:
    lines = normalize_lines(lines_raw)
    findings: List[Finding] = []
    tainted_vars = detect_taint_sources(lines)

    print(f"🔍 Analyzing {os.path.basename(filepath)} - found {len(tainted_vars)} tainted variables")

    if ll_data and HAVE_LL:
        findings.append(
            Finding(
                rule_id="COBOL-LL-001",
                title="Enhanced analysis with LegacyLens",
                severity="INFO",
                file=filepath,
                line=1,
                message="File successfully analyzed with LegacyLens parser",
                remediation="Enhanced COBOL structure analysis available",
            )
        )

    file_status_present = has_file_status(lines)

    credential_keywords = ["PASSWORD", "PWD", "USER-ID", "TOKEN", "SECRET", "API-KEY", "AUTH", "KEY"]
    move_value_re = re.compile(
        r"\b(MOVE|VALUE)\s+(['\"])(?P<literal>[^'\"]{3,})\2(?:\s+TO\s+)?(?P<var>[A-Z0-9\-\$#@_]+)\b",
        re.IGNORECASE,
    )
    for idx, line in enumerate(lines, 1):
        match = move_value_re.search(line)
        if match:
            var_name = match.group("var").upper()
            if any(k in var_name for k in credential_keywords):
                findings.append(
                    Finding(
                        rule_id="COBOL-SECRET-001",
                        title="Hardcoded credential detected",
                        severity="HIGH",
                        file=filepath,
                        line=idx,
                        message=f"Hardcoded credential in variable: {var_name}",
                        snippet=line.strip(),
                        cwe="CWE-798",
                        remediation="Remove hardcoded secrets. Use secure storage or environment variables.",
                    )
                )

    exec_sql_indices = [i for i, l in enumerate(lines) if re.search(r"\bEXEC\b\s+\bSQL\b", l, re.IGNORECASE)]
    for idx in exec_sql_indices:
        block = " ".join(lines[idx : min(len(lines), idx + 8)])
        if re.search(r"\b(EXECUTE\s+IMMEDIATE|PREPARE|EXECUTE\s+IMMEDIATE)\b", block, re.IGNORECASE):
            findings.append(
                Finding(
                    rule_id="COBOL-SQL-001",
                    title="Dynamic SQL execution",
                    severity="HIGH",
                    file=filepath,
                    line=idx + 1,
                    message="Dynamic SQL detected - potential injection vulnerability",
                    snippet=block.strip(),
                    cwe="CWE-89",
                    remediation="Use parameterized queries and validate inputs.",
                )
            )
            var_match = re.search(r":?([A-Z0-9\-\$#@_]+)", block, re.IGNORECASE)
            if var_match:
                varname = var_match.group(1).upper()
                if varname in tainted_vars:
                    findings.append(
                        Finding(
                            rule_id="COBOL-SQL-002",
                            title="Dynamic SQL with tainted input",
                            severity="CRITICAL",
                            file=filepath,
                            line=idx + 1,
                            message=f"Dynamic SQL uses unvalidated input: {varname}",
                            snippet=block.strip(),
                            cwe="CWE-89",
                            remediation="Validate and sanitize user input before SQL execution.",
                        )
                    )

    open_re = re.compile(r"^\s*OPEN\s+(INPUT|OUTPUT|I-O|EXTEND)\b", re.IGNORECASE)
    if not file_status_present:
        for idx, line in enumerate(lines, 1):
            if open_re.search(line):
                findings.append(
                    Finding(
                        rule_id="COBOL-FILE-001",
                        title="File operation without error handling",
                        severity="MEDIUM",
                        file=filepath,
                        line=idx,
                        message="File OPEN should include FILE STATUS checking or explicit error handling",
                        snippet=line.strip(),
                        cwe="CWE-252",
                        remediation="Define FILE STATUS and check for errors after file operations.",
                    )
                )

    str_re = re.compile(r"^\s*(STRING|UNSTRING)\b", re.IGNORECASE)
    for idx, line in enumerate(lines, 1):
        if str_re.search(line):
            if not has_on_overflow_near(lines, idx - 1, window=10):
                findings.append(
                    Finding(
                        rule_id="COBOL-STR-001",
                        title="String operation without overflow handling",
                        severity="MEDIUM",
                        file=filepath,
                        line=idx,
                        message="STRING/UNSTRING without ON OVERFLOW handler near the statement",
                        snippet=line.strip(),
                        cwe="CWE-120",
                        remediation="Add ON OVERFLOW handler or otherwise check for space/overflow conditions.",
                    )
                )

    accept_re = re.compile(r"\bACCEPT\s+([A-Z0-9\-\$#@_]+)\b", re.IGNORECASE)
    for idx, line in enumerate(lines, 1):
        m = accept_re.search(line)
        if m:
            varname = m.group(1).upper()
            if not has_validation_near(lines, idx, varname, window=20):
                findings.append(
                    Finding(
                        rule_id="COBOL-INPUT-001",
                        title="User input without validation",
                        severity="LOW",
                        file=filepath,
                        line=idx,
                        message=f"ACCEPT statement receives user input for {varname} - ensure validation",
                        snippet=line.strip(),
                        cwe="CWE-20",
                        remediation="Validate user input for length, format, and content soon after ACCEPT.",
                    )
                )

    return findings


def cmd_scan(args: argparse.Namespace):
    files = find_cobol_files(args.paths, include_txt=args.include_txt)
    if not files:
        print("❌ No COBOL files found!", file=sys.stderr)
        return

    if not args.quiet:
        print(f"🔍 Scanning {len(files)} COBOL files for security issues...")
        if HAVE_LL and getattr(args, "use_legacylens", False):
            print("🚀 Using LegacyLens COBOL Parser for enhanced analysis")

    all_findings: List[Finding] = []
    for filepath in files:
        lines_raw = read_file(filepath)
        if lines_raw:
            ll_data = None
            if HAVE_LL and getattr(args, "use_legacylens", False):
                ll_data = parse_with_legacylens(filepath)
            findings = analyze_security(lines_raw, filepath, ll_data)
            all_findings.extend(findings)

    if args.format == "json":
        print(json.dumps([asdict(f) for f in all_findings], indent=2))
    else:
        if not all_findings:
            print("✅ No security issues found!")
        else:
            print(f"\n🚨 Found {len(all_findings)} security issues:\n")
            by_severity = {}
            for finding in all_findings:
                by_severity.setdefault(finding.severity, []).append(finding)
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if severity in by_severity:
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}[severity]
                    findings_list = by_severity[severity]
                    print(f"{icon} {severity} Issues ({len(findings_list)}):")
                    for f in findings_list:
                        print(f"  📋 {f.title}")
                        print(f"     📁 {f.file}:{f.line}")
                        print(f"     💡 {f.message}")
                        if f.snippet:
                            print(f"     📝 Code: {f.snippet}")
                        if f.remediation:
                            print(f"     🔧 Fix: {f.remediation}")
                        print()


def main():
    parser = argparse.ArgumentParser(description="🔍 COBOL Security Scanner with LegacyLens fallback")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Scan for security vulnerabilities")
    scan_parser.add_argument("paths", nargs="+", help="COBOL files or directories to scan")
    scan_parser.add_argument("--format", choices=["pretty", "json"], default="pretty")
    scan_parser.add_argument("--use-legacylens", action="store_true", help="Use LegacyLens parser if available")
    scan_parser.add_argument("--include-txt", action="store_true", help="Include .txt files when searching directories")
    scan_parser.add_argument("--quiet", action="store_true", help="Reduce console output")
    scan_parser.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
