# scanner.py
import ast
import os
import re
from typing import List, Dict, Any

class Issue:
    def __init__(self, filepath, lineno, col_offset, issue_type, message, severity="Medium", suggestion=""):
        self.filepath = filepath
        self.lineno = lineno
        self.col_offset = col_offset
        self.issue_type = issue_type
        self.message = message
        self.severity = severity
        self.suggestion = suggestion

    def to_dict(self):
        return {
            "file": self.filepath,
            "lineno": self.lineno,
            "col": self.col_offset,
            "type": self.issue_type,
            "message": self.message,
            "severity": self.severity,
            "suggestion": self.suggestion
        }

# Helper detectors using AST
class PythonScanner(ast.NodeVisitor):
    def __init__(self, filepath):
        self.issues: List[Issue] = []
        self.filepath = filepath
        self.source = open(filepath, "r", encoding="utf-8", errors="ignore").read()

    def visit_Call(self, node):
        # check eval/exec
        try:
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("eval", "exec", "compile"):
                msg = f"Use of {func.id} can lead to code injection."
                sug = "Avoid eval/exec; use ast.literal_eval or explicit parsing."
                self.issues.append(Issue(self.filepath, node.lineno, node.col_offset, func.id.upper(), msg, "High", sug))

            # subprocess(..., shell=True) detection
            if isinstance(func, ast.Attribute):
                if getattr(func, 'attr', "") in ("Popen", "call", "run"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value == True:
                            msg = "subprocess called with shell=True — shell injection risk."
                            sug = "Use list args instead of shell=True or sanitize inputs."
                            self.issues.append(Issue(self.filepath, node.lineno, node.col_offset, "SUBPROCESS_SHELL", msg, "High", sug))
            if isinstance(func, ast.Name) and func.id in ("system",):
                msg = "os.system() may be vulnerable to shell injection."
                sug = "Use subprocess.run([...], check=True) with list arguments."
                self.issues.append(Issue(self.filepath, node.lineno, node.col_offset, "OS_SYSTEM", msg, "High", sug))
        except Exception:
            pass

        # requests(..., verify=False)
        try:
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ("get", "post", "request"):
                    for kw in node.keywords:
                        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value == False:
                            msg = "requests called with verify=False — disables SSL verification."
                            sug = "Avoid verify=False; fix certificate issues properly."
                            self.issues.append(Issue(self.filepath, node.lineno, node.col_offset, "INSECURE_SSL", msg, "High", sug))
        except Exception:
            pass

        self.generic_visit(node)

    def visit_Attribute(self, node):
        self.generic_visit(node)

    def visit_Import(self, node):
        # detect import pickle
        for alias in node.names:
            if alias.name == "pickle":
                msg = "Module 'pickle' imported — can be unsafe when loading untrusted data."
                sug = "Prefer json or use pickle only with trusted sources."
                self.issues.append(Issue(self.filepath, node.lineno, node.col_offset, "PICKLE_IMPORT", msg, "Medium", sug))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module == "pickle":
            msg = "pickle imported via from ... — can be dangerous for untrusted input."
            sug = "Prefer safer formats (e.g., JSON)."
            self.issues.append(Issue(self.filepath, node.lineno, node.col_offset, "PICKLE_IMPORT", msg, "Medium", sug))
        self.generic_visit(node)

    def visit_Assign(self, node):
        # detect likely hardcoded secret: variable name contains 'password' or 'secret' and value is literal
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id.lower()
                if any(k in name for k in ("password", "pwd", "secret", "token", "key")):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        msg = f"Hardcoded secret in variable '{target.id}'."
                        sug = "Remove secret from source; use environment variables or a vault."
                        self.issues.append(Issue(self.filepath, node.lineno, node.col_offset, "HARDCODED_SECRET", msg, "High", sug))
        self.generic_visit(node)

def regex_checks(filepath, source) -> List[Issue]:
    issues=[]
    # SQL concatenation: pattern like execute("..."+var) or f"..." + var
    sql_pattern = re.compile(r"\.execute\(\s*(f?['\"].+['\"]\s*\+|\+?\s*f?['\"].+['\"]\s*)", re.M)
    for m in sql_pattern.finditer(source):
        lineno = source[:m.start()].count("\n") + 1
        msg = "Potential SQL query built via string concatenation — SQL injection risk."
        sug = "Use parameterized queries (e.g., cursor.execute(sql, params))."
        issues.append(Issue(filepath, lineno, 0, "SQL_CONCAT", msg, "High", sug))

    # hashlib.md5 usage
    if "hashlib.md5" in source:
        lineno = source.count("\n", 0, source.find("hashlib.md5")) + 1
        msg = "MD5 used — it's cryptographically weak."
        sug = "Use hashlib.sha256 or stronger algorithms."
        issues.append(Issue(filepath, lineno, 0, "WEAK_HASH", msg, "Medium", sug))

    # use of eval in string (simple)
    if re.search(r"\beval\s*\(", source):
        lineno = source.count("\n", 0, source.find("eval(")) + 1
        issues.append(Issue(filepath, lineno, 0, "EVAL_USE", "eval() used — risk of code injection.", "High", "Avoid eval; use safe parsing."))

    return issues

def scan_file(path) -> List[Issue]:
    issues=[]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        # AST-based
        try:
            tree = ast.parse(source, filename=path)
            scanner = PythonScanner(path)
            scanner.visit(tree)
            issues.extend(scanner.issues)
        except Exception as e:
            # fallback: if parsing fails, we still do regex checks
            issues.append(Issue(path, 0, 0, "PARSE_ERROR", f"Failed to parse AST: {e}", "Low", "Check file syntax."))

        # regex checks
        issues.extend(regex_checks(path, source))

    except Exception as e:
        issues.append(Issue(path, 0, 0, "FILE_ERROR", f"Cannot open/read file: {e}", "Low", "Check file permissions."))
    return issues

def scan_path(path, recursive=True, extensions=(".py",)) -> List[Issue]:
    results=[]
    if os.path.isfile(path):
        if path.endswith(extensions):
            results.extend(scan_file(path))
        return results
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.endswith(extensions):
                full = os.path.join(root, f)
                results.extend(scan_file(full))
        if not recursive:
            break
    return results
