"""
Read-only web dashboard for scan results persisted via --db. Built on
the standard library's http.server — no web framework dependency,
matching this portfolio's minimal-dependency, "real protocol
implementation" approach already used for the mock gateway test
fixtures. Read-only by construction: every route only ever runs
SELECT queries against the SQLite database; nothing here writes to it.
"""

from __future__ import annotations

import html
import http.server
import sqlite3
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from camara_audit.core.storage import list_findings, list_scans, open_db, severity_counts

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEVERITY_COLOR = {
    "CRITICAL": "#b00020", "HIGH": "#d32f2f", "MEDIUM": "#f57c00",
    "LOW": "#0277bd", "INFO": "#616161",
}

_PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>camara-audit dashboard</title>
<style>
  body {{ font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem;
          background: #fafafa; color: #222; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .subtitle {{ color: #666; margin-top: 0; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; background: white; }}
  th, td {{ text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #eee; }}
  th {{ background: #f0f0f0; }}
  .sev {{ color: white; padding: 0.1rem 0.5rem; border-radius: 4px;
          font-size: 0.85em; font-weight: 600; white-space: nowrap; }}
  .counts span {{ margin-right: 1rem; }}
  form {{ margin-top: 1rem; }}
  a {{ color: #1565c0; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<h1>\U0001F4E1 camara-audit dashboard</h1>
<p class="subtitle">Read-only view of scans persisted via --db. {scan_count} scan(s) recorded.</p>
<p class="counts">{counts_html}</p>
{filter_html}
{table_html}
</body>
</html>
"""


def _severity_badge(sev: str) -> str:
    color = _SEVERITY_COLOR.get(sev, "#616161")
    return f'<span class="sev" style="background:{color}">{html.escape(sev)}</span>'


def render_page(conn: sqlite3.Connection, severity: str | None, module: str | None) -> bytes:
    scans = list_scans(conn)
    counts = severity_counts(conn)
    findings = list_findings(conn, severity=severity, module=module)

    counts_html = "".join(
        f"<span>{_severity_badge(sev)} {counts.get(sev, 0)}</span>" for sev in _SEVERITY_ORDER
    )

    modules = sorted({row["module"] for row in scans})
    module_options = "".join(
        f'<option value="{html.escape(m)}"{" selected" if m == module else ""}>{html.escape(m)}</option>'
        for m in modules
    )
    severity_options = "".join(
        f'<option value="{s}"{" selected" if s == severity else ""}>{s}</option>' for s in _SEVERITY_ORDER
    )
    filter_html = (
        '<form method="get">'
        f'<label>Severity: <select name="severity" onchange="this.form.submit()">'
        f'<option value="">(all)</option>{severity_options}</select></label>'
        f'<label style="margin-left:1rem">Module: <select name="module" onchange="this.form.submit()">'
        f'<option value="">(all)</option>{module_options}</select></label>'
        "</form>"
    )

    if not findings:
        table_html = "<p>No findings match this filter.</p>"
    else:
        rows = "".join(
            "<tr>"
            f"<td>{_severity_badge(row['severity'])}</td>"
            f"<td>{html.escape(row['module'])}</td>"
            f"<td>{html.escape(row['title'])}</td>"
            f"<td>{html.escape(row['target'])}</td>"
            f"<td>{html.escape(row['engagement_id'])}</td>"
            "</tr>"
            for row in findings
        )
        table_html = (
            "<table><tr><th>Severity</th><th>Module</th><th>Title</th>"
            "<th>Target</th><th>Engagement</th></tr>" + rows + "</table>"
        )

    return _PAGE.format(
        scan_count=len(scans), counts_html=counts_html,
        filter_html=filter_html, table_html=table_html,
    ).encode("utf-8")


def _make_handler(db_path: str | Path) -> type[http.server.BaseHTTPRequestHandler]:
    class DashboardHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # keep server output quiet

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path != "/":
                self.send_response(404)
                self.end_headers()
                return

            query = parse_qs(parsed.query)
            severity = (query.get("severity") or [""])[0] or None
            module = (query.get("module") or [""])[0] or None

            conn = open_db(db_path)
            try:
                body = render_page(conn, severity, module)
            finally:
                conn.close()

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return DashboardHandler


class DashboardServer:
    """A real HTTP server (no framework) wrapping the dashboard —
    class-based start()/stop() to match this portfolio's mock-gateway
    testing pattern, letting tests spin it up on an ephemeral port
    (port=0) and issue real HTTP requests against it."""

    def __init__(self, db_path: str | Path, host: str = "127.0.0.1", port: int = 0):
        self._server = http.server.HTTPServer((host, port), _make_handler(db_path))
        self.port = self._server.server_address[1]
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def serve_dashboard(db_path: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Blocking entry point used by the CLI — runs until interrupted."""
    http.server.HTTPServer((host, port), _make_handler(db_path)).serve_forever()
