from datetime import datetime, timezone
import json
import sqlite3

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
DB_PATH = "assetwatch.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                hostname TEXT PRIMARY KEY,
                os_name TEXT,
                os_version TEXT,
                last_hotfix TEXT,
                firewall_json TEXT,
                smbv1 TEXT,
                admins_json TEXT,
                ports_json TEXT,
                baseline_ports_json TEXT,
                risk_score INTEGER,
                status TEXT,
                findings_json TEXT,
                last_seen TEXT
            )
        """)


def parse_date(value):
    if not value:
        return None

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def normalize_ports(ports):
    return sorted({int(port) for port in ports})


def evaluate_risk(data, baseline_ports):
    score = 0
    findings = []

    firewall = data.get("firewall_profiles", {})
    disabled_profiles = [name for name, enabled in firewall.items() if not enabled]

    if disabled_profiles:
        score += 35
        findings.append({
            "severity": "HIGH",
            "message": f"Firewall disabled: {', '.join(disabled_profiles)}",
        })

    smbv1 = str(data.get("smbv1", "Unknown"))
    if "enabled" in smbv1.lower():
        score += 35
        findings.append({"severity": "HIGH", "message": "SMBv1 is enabled"})

    hotfix_date = parse_date(data.get("last_hotfix"))
    if hotfix_date:
        age_days = (datetime.now(timezone.utc) - hotfix_date).days
        if age_days > 45:
            score += 20
            findings.append({
                "severity": "MEDIUM",
                "message": f"Latest reported hotfix is {age_days} days old",
            })
    else:
        findings.append({
            "severity": "INFO",
            "message": "Latest hotfix date unavailable",
        })

    current_ports = normalize_ports(data.get("listening_ports", []))
    baseline = set(normalize_ports(baseline_ports))

    # Ignore the Windows dynamic/private port range to avoid noisy alerts.
    new_service_ports = [
        port for port in current_ports
        if port not in baseline and port < 49152
    ]

    if new_service_ports:
        score += min(30, len(new_service_ports) * 10)
        findings.append({
            "severity": "MEDIUM",
            "message": "New listening port(s): " + ", ".join(map(str, new_service_ports)),
        })

    score = min(score, 100)
    status = "RED" if score >= 50 else "YELLOW" if score >= 20 else "GREEN"

    return score, status, findings, current_ports


@app.post("/api/report")
def report():
    data = request.get_json(silent=True) or {}
    hostname = str(data.get("hostname", "")).strip()

    if not hostname:
        return jsonify({"error": "hostname required"}), 400

    current_ports = normalize_ports(data.get("listening_ports", []))

    with get_db() as conn:
        row = conn.execute(
            "SELECT baseline_ports_json FROM assets WHERE hostname = ?",
            (hostname,),
        ).fetchone()

        baseline_ports = (
            json.loads(row["baseline_ports_json"])
            if row
            else current_ports
        )

        score, status, findings, current_ports = evaluate_risk(data, baseline_ports)
        now = datetime.now(timezone.utc).isoformat()

        conn.execute(
            """
            INSERT INTO assets (
                hostname, os_name, os_version, last_hotfix,
                firewall_json, smbv1, admins_json, ports_json,
                baseline_ports_json, risk_score, status,
                findings_json, last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                os_name = excluded.os_name,
                os_version = excluded.os_version,
                last_hotfix = excluded.last_hotfix,
                firewall_json = excluded.firewall_json,
                smbv1 = excluded.smbv1,
                admins_json = excluded.admins_json,
                ports_json = excluded.ports_json,
                risk_score = excluded.risk_score,
                status = excluded.status,
                findings_json = excluded.findings_json,
                last_seen = excluded.last_seen
            """,
            (
                hostname,
                data.get("os_name", "Unknown"),
                data.get("os_version", "Unknown"),
                data.get("last_hotfix"),
                json.dumps(data.get("firewall_profiles", {})),
                data.get("smbv1", "Unknown"),
                json.dumps(data.get("local_admins", [])),
                json.dumps(current_ports),
                json.dumps(baseline_ports),
                score,
                status,
                json.dumps(findings),
                now,
            ),
        )

    return jsonify({
        "ok": True,
        "hostname": hostname,
        "risk_score": score,
        "status": status,
        "findings": findings,
    })


@app.get("/")
def dashboard():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM assets ORDER BY hostname").fetchall()

    now = datetime.now(timezone.utc)
    assets = []

    for row in rows:
        asset = dict(row)
        asset["firewall_profiles"] = json.loads(asset.pop("firewall_json"))
        asset["local_admins"] = json.loads(asset.pop("admins_json"))
        asset["listening_ports"] = json.loads(asset.pop("ports_json"))
        asset["findings"] = json.loads(asset.pop("findings_json"))

        last_seen = parse_date(asset["last_seen"])
        asset["online"] = bool(
            last_seen and (now - last_seen).total_seconds() < 180
        )
        assets.append(asset)

    return render_template("index.html", assets=assets)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
