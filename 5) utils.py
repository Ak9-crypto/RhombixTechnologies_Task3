# utils.py
import json
import os
from jinja2 import Template
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter

HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Rhombix Debugger Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #0078D7; color: white; }
    pre.code { background: #f5f5f5; padding: 10px; overflow-x:auto; }
    .severity-High { color: #b00000; font-weight: bold; }
    .severity-Medium { color: #e09100; }
    .severity-Low { color: #2b7a2b; }
  </style>
</head>
<body>
  <h1>Rhombix Debugger Report</h1>
  <p>Scanned path: {{ path }}</p>
  <p>Total issues: {{ issues|length }}</p>
  <table>
    <tr><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Message</th><th>Suggestion</th></tr>
    {% for i in issues %}
    <tr>
      <td>{{ i.file }}</td>
      <td>{{ i.lineno }}</td>
      <td>{{ i.type }}</td>
      <td class="severity-{{ i.severity }}">{{ i.severity }}</td>
      <td>{{ i.message }}</td>
      <td>{{ i.suggestion }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""

def export_json(issues, outpath="report.json"):
    data = [i.to_dict() for i in issues]
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return outpath

def export_html(issues, scanned_path, outpath="report.html"):
    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(issues=[i.to_dict() for i in issues], path=scanned_path)
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    return outpath
