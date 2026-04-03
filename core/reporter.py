import json
import datetime

from colorama import Fore, Style

class Reporter:
    def __init__(self, target: str):
        self.target   = target
        self.findings = []
        self.started  = datetime.datetime.now()

    def add_finding(self, method: str, path: str, payload: dict,
                    reason: str, response: str, severity: str):
        self.findings.append({
            "id"        : len(self.findings) + 1,
            "timestamp" : datetime.datetime.now().isoformat(),
            "method"    : method,
            "path"      : path,
            "payload"   : payload,
            "reason"    : reason,
            "response"  : response[:500],
            "severity"  : severity,
        })

    def generate_json(self, output_path: str = "report.json"):
        report = {
            "target"    : self.target,
            "started"   : self.started.isoformat(),
            "finished"  : datetime.datetime.now().isoformat(),
            "total"     : len(self.findings),
            "summary"   : self._summary(),
            "findings"  : self.findings,
        }
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"{Fore.GREEN}[+] JSON report saved → {output_path}{Style.RESET_ALL}")

    def _summary(self) -> dict:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            severity = f.get("severity", "low")
            if severity in summary:
                summary[severity] += 1
        return summary

    def generate_html(self, output_path: str = "report.html"):
        summary  = self._summary()
        duration = (datetime.datetime.now() - self.started).seconds

        # Severity colors
        sev_colors = {
            "critical" : "#ff4444",
            "high"     : "#ff8800",
            "medium"   : "#ffcc00",
            "low"      : "#44bb44",
        }

        # Findings rows
        rows = ""
        for f in self.findings:
            color   = sev_colors.get(f["severity"], "#ccc")
            payload = json.dumps(f["payload"], indent=2)
            rows += f"""
            <tr>
                <td>{f['id']}</td>
                <td><span class="badge" style="background:{color}">{f['severity'].upper()}</span></td>
                <td><span class="method {f['method'].lower()}">{f['method']}</span></td>
                <td><code>{f['path']}</code></td>
                <td><pre>{payload}</pre></td>
                <td>{f['reason']}</td>
                <td><pre class="snippet">{f['response'][:200]}</pre></td>
                <td>{f['timestamp'][11:19]}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Fuzzer Report — {self.target}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 2rem;
        }}
        h1 {{ color: #58a6ff; margin-bottom: 0.5rem; }}
        .meta {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 2rem; }}

        /* Summary cards */
        .cards {{
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            flex: 1;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            text-align: center;
            background: #161b22;
            border: 1px solid #30363d;
        }}
        .card .count {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        .card .label {{
            font-size: 0.8rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .critical .count {{ color: #ff4444; }}
        .high     .count {{ color: #ff8800; }}
        .medium   .count {{ color: #ffcc00; }}
        .low      .count {{ color: #44bb44; }}
        .total    .count {{ color: #58a6ff; }}

        /* Table */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }}
        th {{
            background: #161b22;
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 2px solid #30363d;
            color: #58a6ff;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 1px;
        }}
        td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid #21262d;
            vertical-align: top;
        }}
        tr:hover td {{ background: #161b22; }}

        /* Badges */
        .badge {{
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            color: #fff;
        }}
        .method {{
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
        }}
        .get    {{ background: #1f6feb; color: #fff; }}
        .post   {{ background: #238636; color: #fff; }}
        .put    {{ background: #9e6a03; color: #fff; }}
        .patch  {{ background: #6e40c9; color: #fff; }}
        .delete {{ background: #b62324; color: #fff; }}

        pre {{
            white-space: pre-wrap;
            word-break: break-all;
            font-size: 0.78rem;
            color: #8b949e;
        }}
        .snippet {{
            max-height: 80px;
            overflow: hidden;
            color: #3fb950;
        }}
        code {{
            background: #161b22;
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            color: #79c0ff;
        }}

        /* Filter bar */
        .filters {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }}
        .filter-btn {{
            padding: 0.4rem 1rem;
            border-radius: 4px;
            border: 1px solid #30363d;
            background: #161b22;
            color: #c9d1d9;
            cursor: pointer;
            font-size: 0.8rem;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: #21262d;
            border-color: #58a6ff;
            color: #58a6ff;
        }}
        .hidden {{ display: none; }}
    </style>
</head>
<body>
    <h1>🔍 Fuzzer Report</h1>
    <div class="meta">
        Target: <strong>{self.target}</strong> &nbsp;|&nbsp;
        Started: {self.started.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
        Duration: {duration}s &nbsp;|&nbsp;
        Findings: {len(self.findings)}
    </div>

    <!-- Summary cards -->
    <div class="cards">
        <div class="card total">
            <div class="count">{len(self.findings)}</div>
            <div class="label">Total</div>
        </div>
        <div class="card critical">
            <div class="count">{summary['critical']}</div>
            <div class="label">Critical</div>
        </div>
        <div class="card high">
            <div class="count">{summary['high']}</div>
            <div class="label">High</div>
        </div>
        <div class="card medium">
            <div class="count">{summary['medium']}</div>
            <div class="label">Medium</div>
        </div>
        <div class="card low">
            <div class="count">{summary['low']}</div>
            <div class="label">Low</div>
        </div>
    </div>

    <!-- Filters -->
    <div class="filters">
        <button class="filter-btn active" onclick="filterTable('all')">All</button>
        <button class="filter-btn" onclick="filterTable('critical')">Critical</button>
        <button class="filter-btn" onclick="filterTable('high')">High</button>
        <button class="filter-btn" onclick="filterTable('medium')">Medium</button>
        <button class="filter-btn" onclick="filterTable('low')">Low</button>
    </div>

    <!-- Findings table -->
    <table id="findings-table">
        <thead>
            <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Method</th>
                <th>Path</th>
                <th>Payload</th>
                <th>Reason</th>
                <th>Response</th>
                <th>Time</th>
            </tr>
        </thead>
        <tbody>
            {rows if rows else '<tr><td colspan="8" style="text-align:center;color:#8b949e">No findings</td></tr>'}
        </tbody>
    </table>

    <script>
        function filterTable(severity) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            document.querySelectorAll('#findings-table tbody tr').forEach(row => {{
                if (severity === 'all') {{
                    row.classList.remove('hidden');
                }} else {{
                    const badge = row.querySelector('.badge');
                    const match = badge && badge.textContent.toLowerCase() === severity;
                    row.classList.toggle('hidden', !match);
                }}
            }});
        }}
    </script>
</body>
</html>"""

        with open(output_path, 'w') as f:
            f.write(html)
        print(f"{Fore.GREEN}[+] HTML report saved → {output_path}{Style.RESET_ALL}")

    def print_summary(self):
        summary  = self._summary()
        duration = (datetime.datetime.now() - self.started).seconds

        print(f"\n{Fore.CYAN}{'═' * 72}")
        print(f"  FINAL REPORT SUMMARY")
        print(f"{'═' * 72}")
        print(f"  Target   : {self.target}")
        print(f"  Duration : {duration}s")
        print(f"  Total    : {len(self.findings)} findings")
        print(f"{'─' * 72}")
        print(f"  {Fore.RED}Critical : {summary['critical']}")
        print(f"  {Fore.YELLOW}High     : {summary['high']}")
        print(f"  {Fore.WHITE}Medium   : {summary['medium']}")
        print(f"  {Fore.GREEN}Low      : {summary['low']}")
        print(f"{Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")