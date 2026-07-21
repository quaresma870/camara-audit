"""camara-audit CLI."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()

_TEMPLATE = """\
# camara-audit authorization file.
#
# This file does not authorize anything until every field below is
# filled in truthfully and explicit, written sign-off has been
# obtained from the owner of every target listed in scope.targets.
# camara-audit will refuse to run a single probe without a validated
# file like this one.

engagement_id: ""
authorized_by: ""
authorized_contact_email: ""
client: ""

scope:
  targets:
    - ""                     # e.g. "https://api.operator.com/oauth2/token"
  excluded_targets: []
  allowed_categories:
    - recon                  # read-only endpoint probing only

window:
  start: ""                  # ISO 8601, e.g. "2026-01-01T00:00:00+00:00"
  end: ""

confirmation_phrase: ""

# rate_limits:
#   max_total_requests: 2000
#   max_per_second: 20.0
"""


@click.group()
@click.version_option(package_name="camara-audit")
def cli():
    """📡 camara-audit — authorized CAMARA/Open Gateway API security auditing."""


@cli.command()
@click.option("--output", "-o", default="authorization.yml", show_default=True)
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
def init(output, force):
    """Create an authorization.yml template."""
    path = Path(output)
    if path.exists() and not force:
        console.print(f"[red]{path} already exists.[/red] Use --force to overwrite.")
        sys.exit(1)
    path.write_text(_TEMPLATE, encoding="utf-8")
    console.print(f"[green]✔[/green] Template written: [bold]{path}[/bold]")
    console.print(
        "\n[yellow]This file does not authorize anything yet.[/yellow] "
        "Fill in every field, get explicit sign-off from the target owner, then run:\n"
        f"  [cyan]camara-audit validate-scope --authorization {path}[/cyan]\n"
    )


@cli.command(name="validate-scope")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True)
def validate_scope(authorization):
    """Validate an authorization.yml — schema, time window, and scope."""
    from camara_audit.core.authorization import AuthorizationError, load_authorization

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    console.print(f"[green]✔[/green] Valid authorization file: [bold]{authorization}[/bold]")
    console.print(f"  Engagement: {auth.engagement_id} ({auth.client})")
    console.print(f"  Targets: {', '.join(auth.scope.targets)}")
    console.print(f"  Categories: {', '.join(auth.scope.allowed_categories) or '(none)'}")
    if not auth.is_within_window():
        console.print("  [yellow]⚠ Current time is outside this authorization's window.[/yellow]")


@cli.command(name="list-plugins")
def list_plugins():
    """List all available plugins and their tier."""
    console.print("\n[bold]Available plugins[/bold]\n")
    console.print("  token_endpoint_security           [cyan]recon[/cyan]")
    console.print("  number_verification_enumeration   [cyan]recon[/cyan]")
    console.print("  sim_swap_rate_limit               [cyan]recon[/cyan]")
    console.print("  device_location_accuracy_floor    [cyan]recon[/cyan]")
    console.print()


@cli.command()
@click.option("--db", "db_path", required=True, type=click.Path(exists=True, dir_okay=False),
              help="Path to a SQLite database previously populated via --db on a scan/"
                   "analyze-token command.")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8765, show_default=True, type=int)
def dashboard(db_path, host, port):
    """Serve a read-only local web dashboard over a --db SQLite file.

    Read-only: every route only ever runs SELECT queries against the
    database — nothing served by this command writes to it.
    """
    from camara_audit.reports.dashboard import serve_dashboard

    console.print(
        f"[green]✔[/green] Serving dashboard at [bold]http://{host}:{port}/[/bold] "
        "(read-only, Ctrl+C to stop)"
    )
    try:
        serve_dashboard(db_path, host=host, port=port)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")


@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--authorization", "-a", default="authorization.yml", show_default=True)
@click.option("--audit-log", default=None)
@click.option("--timeout", default=10.0, show_default=True, type=float)
@click.option("--insecure", is_flag=True,
              help="Skip TLS certificate verification — needed to reach a self-signed or "
                   "otherwise unverifiable target at all.")
@click.option("--json", "json_output", default=None, type=click.Path(),
              help="Also write findings as JSON to this path — a more robust way to check "
                   "results programmatically than parsing the terminal table's word-wrapped text.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Persist findings to a SQLite database at this path, for later viewing "
                   "with `camara-audit dashboard --db <path>`.")
def scan(targets, authorization, audit_log, timeout, insecure, json_output, db_path):
    """Scan one or more CAMARA/Open Gateway token endpoint URLs."""
    from camara_audit.core.authorization import AuthorizationError, load_authorization
    from camara_audit.core.engagement import Engagement, ScopeViolation
    from camara_audit.core.storage import open_db, record_result
    from camara_audit.plugins.token_endpoint_security import TokenEndpointSecurityModule
    from camara_audit.reports.terminal import print_results

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    log_path = audit_log or f"{auth.engagement_id}.audit.jsonl"
    eng = Engagement(auth, log_path)
    db_conn = open_db(db_path) if db_path else None

    all_findings = []
    exit_code = 0
    for target in targets:
        plugin = TokenEndpointSecurityModule(eng, timeout=timeout, tls_verify=not insecure)
        try:
            result = plugin.run(target)
        except ScopeViolation as exc:
            console.print(f"[red]✘ {exc}[/red]")
            exit_code = 1
            continue
        if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
            exit_code = 1
        all_findings.extend(result.findings)
        print_results(target, [result])
        if db_conn:
            record_result(db_conn, auth.engagement_id, target, result)

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump([f.to_dict() for f in all_findings], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(all_findings)} finding(s) to {json_output}")

    if db_conn:
        db_conn.close()
        console.print(f"[green]✔[/green] Persisted results to {db_path}")

    sys.exit(exit_code)


@cli.command(name="scan-number-verification")
@click.argument("targets", nargs=-1, required=True)
@click.option("--authorization", "-a", default="authorization.yml", show_default=True)
@click.option("--audit-log", default=None)
@click.option("--timeout", default=10.0, show_default=True, type=float)
@click.option("--insecure", is_flag=True,
              help="Skip TLS certificate verification — needed to reach a self-signed or "
                   "otherwise unverifiable target at all.")
@click.option("--phone-number", default="+15550123456", show_default=True,
              help="Syntactically valid but non-real phone number used to probe the endpoint.")
@click.option("--json", "json_output", default=None, type=click.Path(),
              help="Also write findings as JSON to this path.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Persist findings to a SQLite database at this path, for later viewing "
                   "with `camara-audit dashboard --db <path>`.")
def scan_number_verification(
    targets, authorization, audit_log, timeout, insecure, phone_number, json_output, db_path,
):
    """Scan one or more CAMARA Number Verification `verify` endpoint URLs for
    phone-number-echo enumeration in error responses."""
    from camara_audit.core.authorization import AuthorizationError, load_authorization
    from camara_audit.core.engagement import Engagement, ScopeViolation
    from camara_audit.core.storage import open_db, record_result
    from camara_audit.plugins.number_verification_enumeration import (
        NumberVerificationEnumerationModule,
    )
    from camara_audit.reports.terminal import print_results

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    log_path = audit_log or f"{auth.engagement_id}.audit.jsonl"
    eng = Engagement(auth, log_path)
    db_conn = open_db(db_path) if db_path else None

    all_findings = []
    exit_code = 0
    for target in targets:
        plugin = NumberVerificationEnumerationModule(eng, timeout=timeout, tls_verify=not insecure)
        try:
            result = plugin.run(target, phone_number=phone_number)
        except ScopeViolation as exc:
            console.print(f"[red]✘ {exc}[/red]")
            exit_code = 1
            continue
        if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
            exit_code = 1
        all_findings.extend(result.findings)
        print_results(target, [result])
        if db_conn:
            record_result(db_conn, auth.engagement_id, target, result)

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump([f.to_dict() for f in all_findings], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(all_findings)} finding(s) to {json_output}")

    if db_conn:
        db_conn.close()
        console.print(f"[green]✔[/green] Persisted results to {db_path}")

    sys.exit(exit_code)


@cli.command(name="scan-sim-swap")
@click.argument("targets", nargs=-1, required=True)
@click.option("--authorization", "-a", default="authorization.yml", show_default=True)
@click.option("--audit-log", default=None)
@click.option("--timeout", default=10.0, show_default=True, type=float)
@click.option("--insecure", is_flag=True,
              help="Skip TLS certificate verification — needed to reach a self-signed or "
                   "otherwise unverifiable target at all.")
@click.option("--phone-number", default="+15550123456", show_default=True,
              help="Syntactically valid but non-real phone number used to probe the endpoint.")
@click.option("--probe-count", default=20, show_default=True, type=int,
              help="Number of consecutive requests to send for the same phone number.")
@click.option("--json", "json_output", default=None, type=click.Path(),
              help="Also write findings as JSON to this path.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Persist findings to a SQLite database at this path, for later viewing "
                   "with `camara-audit dashboard --db <path>`.")
def scan_sim_swap(
    targets, authorization, audit_log, timeout, insecure, phone_number, probe_count, json_output, db_path,
):
    """Scan one or more CAMARA SIM Swap `check` endpoint URLs for missing
    per-phone-number rate limiting (a surveillance-oracle risk)."""
    from camara_audit.core.authorization import AuthorizationError, load_authorization
    from camara_audit.core.engagement import Engagement, ScopeViolation
    from camara_audit.core.storage import open_db, record_result
    from camara_audit.plugins.sim_swap_rate_limit import SimSwapRateLimitModule
    from camara_audit.reports.terminal import print_results

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    log_path = audit_log or f"{auth.engagement_id}.audit.jsonl"
    eng = Engagement(auth, log_path)
    db_conn = open_db(db_path) if db_path else None

    all_findings = []
    exit_code = 0
    for target in targets:
        plugin = SimSwapRateLimitModule(eng, timeout=timeout, tls_verify=not insecure)
        try:
            result = plugin.run(target, phone_number=phone_number, probe_count=probe_count)
        except ScopeViolation as exc:
            console.print(f"[red]✘ {exc}[/red]")
            exit_code = 1
            continue
        if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
            exit_code = 1
        all_findings.extend(result.findings)
        print_results(target, [result])
        if db_conn:
            record_result(db_conn, auth.engagement_id, target, result)

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump([f.to_dict() for f in all_findings], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(all_findings)} finding(s) to {json_output}")

    if db_conn:
        db_conn.close()
        console.print(f"[green]✔[/green] Persisted results to {db_path}")

    sys.exit(exit_code)


@cli.command(name="scan-device-location")
@click.argument("targets", nargs=-1, required=True)
@click.option("--authorization", "-a", default="authorization.yml", show_default=True)
@click.option("--audit-log", default=None)
@click.option("--timeout", default=10.0, show_default=True, type=float)
@click.option("--insecure", is_flag=True,
              help="Skip TLS certificate verification — needed to reach a self-signed or "
                   "otherwise unverifiable target at all.")
@click.option("--phone-number", default="+15550123456", show_default=True,
              help="Syntactically valid but non-real phone number used to probe the endpoint.")
@click.option("--json", "json_output", default=None, type=click.Path(),
              help="Also write findings as JSON to this path.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Persist findings to a SQLite database at this path, for later viewing "
                   "with `camara-audit dashboard --db <path>`.")
def scan_device_location(
    targets, authorization, audit_log, timeout, insecure, phone_number, json_output, db_path,
):
    """Scan one or more CAMARA Device Location Verification `verify` endpoint
    URLs for missing area-radius/accuracy-floor enforcement."""
    from camara_audit.core.authorization import AuthorizationError, load_authorization
    from camara_audit.core.engagement import Engagement, ScopeViolation
    from camara_audit.core.storage import open_db, record_result
    from camara_audit.plugins.device_location_accuracy_floor import (
        DeviceLocationAccuracyFloorModule,
    )
    from camara_audit.reports.terminal import print_results

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    log_path = audit_log or f"{auth.engagement_id}.audit.jsonl"
    eng = Engagement(auth, log_path)
    db_conn = open_db(db_path) if db_path else None

    all_findings = []
    exit_code = 0
    for target in targets:
        plugin = DeviceLocationAccuracyFloorModule(eng, timeout=timeout, tls_verify=not insecure)
        try:
            result = plugin.run(target, phone_number=phone_number)
        except ScopeViolation as exc:
            console.print(f"[red]✘ {exc}[/red]")
            exit_code = 1
            continue
        if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
            exit_code = 1
        all_findings.extend(result.findings)
        print_results(target, [result])
        if db_conn:
            record_result(db_conn, auth.engagement_id, target, result)

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump([f.to_dict() for f in all_findings], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(all_findings)} finding(s) to {json_output}")

    if db_conn:
        db_conn.close()
        console.print(f"[green]✔[/green] Persisted results to {db_path}")

    sys.exit(exit_code)


@cli.command(name="analyze-token")
@click.argument("token")
@click.option("--json", "json_output", default=None, type=click.Path())
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Persist findings to a SQLite database at this path, for later viewing "
                   "with `camara-audit dashboard --db <path>`.")
def analyze_token(token, json_output, db_path):
    """Analyze a JWT (access/ID token) for PII leakage in its claims.

    File/data analysis only — no live target is touched, so no
    authorization.yml is needed for this command. Pass the raw token
    string, or '@path/to/file' to read it from a file.
    """
    from camara_audit.analyzers.jwt_pii import analyze_jwt_for_pii
    from camara_audit.core.models import ModuleResult
    from camara_audit.reports.terminal import print_results

    if token.startswith("@"):
        token = Path(token[1:]).read_text(encoding="utf-8").strip()

    result = ModuleResult(module="jwt_pii_leakage", findings=analyze_jwt_for_pii(token, source_label="token"))
    findings = result.findings
    print_results("token", [result])

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump([f.to_dict() for f in findings], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(findings)} finding(s) to {json_output}")

    if db_path:
        from camara_audit.core.storage import open_db, record_result

        db_conn = open_db(db_path)
        record_result(db_conn, "offline-analysis", "token", result)
        db_conn.close()
        console.print(f"[green]✔[/green] Persisted results to {db_path}")

    if any(f.severity.value == "CRITICAL" for f in findings):
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
