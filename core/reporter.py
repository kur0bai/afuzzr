from jinja2 import Template


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>afuzzr Report</title>
    <style>
        body { font-family: sans-serif; background-color: #f4f4f4; color: #333; }
        .container { max-width: 900px; margin: 2em auto; background: white; padding: 2em; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #d9534f; }
        h2 { border-bottom: 2px solid #eee; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 1em; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }
        th { background-color: #f2f2f2; }
        .critical { border-left: 5px solid #d9534f; }
        .high { border-left: 5px solid #f0ad4e; }
        .medium { border-left: 5px solid #5bc0de; }
        .payload { word-break: break-all; background-color: #f9f2f4; padding: 5px; }
        .response { max-height: 150px; overflow-y: auto; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>API Fuzzer Report</h1>
        <p>Generated on: {{ timestamp }}</p>
        <h2>Findings ({{ findings|length }})</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Endpoint</th>
                    <th>Payload</th>
                    <th>Reason</th>
                    <th>Response Snippet</th>
                </tr>
            </thead>
            <tbody>
                {% for finding in findings %}
                <tr class="{{ finding.severity }}">
                    <td>{{ finding.severity.upper() }}</td>
                    <td>{{ finding.method }} {{ finding.path }}</td>
                    <td class="payload">{{ finding.payload }}</td>
                    <td>{{ finding.reason }}</td>
                    <td class="response">{{ finding.response_snippet }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

class Reporter:
    def __init__(self):
        self.findings = []

    def add_finding(self, method, path, payload, reason, response_text, severity="medium"):
        self.findings.append({
            "method": method,
            "path": path,
            "payload": payload,
            "reason": reason,
            "response_snippet": response_text[:500] + "..." if len(response_text) > 500 else response_text,
            "severity": severity
        })

    def save_report(self, filename="fuzzer_report.html"):
        from datetime import datetime
        template = Template(HTML_TEMPLATE)
        html_output = template.render(
            findings=self.findings,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        with open(filename, "w") as f:
            f.write(html_output)
        print(f"[+] Report saved to {filename}\n")