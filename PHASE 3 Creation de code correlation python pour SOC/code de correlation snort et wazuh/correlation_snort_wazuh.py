#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
from datetime import datetime
from flask import Flask, render_template_string, send_file

# ========= CONFIG SIMPLE =========
SNORT_ALERT_PATH = "/var/log/snort/snort.alert.fast"
WAZUH_ALERTS_JSON_PATH = "/var/ossec/logs/alerts/alerts.json"
REPORT_DIR = "/home/soc/correlation/reports"
PORT = 5001
HOST = "0.0.0.0"

app = Flask(__name__)

# ========= LECTURE SIMPLE =========
def count_snort_events(path: str) -> int:
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f if _.strip())
    except Exception:
        return 0

def count_wazuh_events(path: str) -> int:
    if not os.path.exists(path):
        return 0
    count = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if "rule" in obj:
                        count += 1
                except Exception:
                    continue
        return count
    except Exception:
        return 0

def extract_top_ips_from_snort(path: str, limit: int = 5):
    """
    Simple : cherche des IP dans les lignes snort et compte l'IP source.
    (pas besoin d'un parsing parfait)
    """
    import re
    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})")

    counts = {}
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = ip_re.search(line)
                if m:
                    src = m.group(1)
                    counts[src] = counts.get(src, 0) + 1
    except Exception:
        pass

    # tri décroissant
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return items[:limit]

def compute_results():
    """
    Résultats simples :
    - total snort
    - total wazuh
    - affichage par IP (top IPs snort)
    - correlation level simple = snort_count (par IP) + wazuh_total (global)
      (simple et académique, suffisant bac+3)
    """
    snort_total = count_snort_events(SNORT_ALERT_PATH)
    wazuh_total = count_wazuh_events(WAZUH_ALERTS_JSON_PATH)

    top_ips = extract_top_ips_from_snort(SNORT_ALERT_PATH, limit=10)

    results = []
    for ip, sn_count in top_ips:
        corr_level = sn_count + wazuh_total
        results.append({
            "ip": ip,
            "snort": sn_count,
            "wazuh": wazuh_total,   # simple (global)
            "level": corr_level
        })

    # si rien trouvé, mettre IP 0.0.0.0
    if not results:
        results = [{
            "ip": "0.0.0.0",
            "snort": snort_total,
            "wazuh": wazuh_total,
            "level": snort_total + wazuh_total
        }]

    return snort_total, wazuh_total, results


# ========= HTML PAGE (UI PRO SOC) =========
PAGE_HTML = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Correlation - Snort & Wazuh</title>
<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Courier New', 'JetBrains Mono', monospace;
  background: linear-gradient(135deg, #0a0e27 0%, #1a1a3e 50%, #0f1a2e 100%);
  color: #e0e0e0;
  min-height: 100vh;
  padding: 20px;
  overflow-x: hidden;
}

.container {
  max-width: 1400px;
  margin: 0 auto;
  background: rgba(15, 26, 46, 0.8);
  backdrop-filter: blur(10px);
  border: 2px solid #00ff88;
  border-radius: 12px;
  padding: 40px;
  box-shadow: 0 0 40px rgba(0, 255, 136, 0.2), inset 0 0 20px rgba(0, 255, 136, 0.05);
  animation: fadeIn 0.8s ease-in;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

.header {
  text-align: center;
  margin-bottom: 40px;
  border-bottom: 2px solid #00ff88;
  padding-bottom: 20px;
  animation: slideDown 0.6s ease-out;
}

@keyframes slideDown {
  from { opacity: 0; transform: translateY(-20px); }
  to { opacity: 1; transform: translateY(0); }
}

.header h1 {
  font-size: 2.8em;
  background: linear-gradient(45deg, #00ff88, #00ccff, #00ff88);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
  margin-bottom: 10px;
  letter-spacing: 2px;
}

.header p {
  color: #00ff88;
  font-size: 0.95em;
  font-weight: bold;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
  animation: slideUp 0.6s ease-out;
}

.stat-card {
  background: rgba(0, 255, 136, 0.05);
  border: 2px solid #00ff88;
  border-radius: 8px;
  padding: 25px;
  text-align: center;
  transition: all 0.3s ease;
  box-shadow: 0 0 20px rgba(0, 255, 136, 0.1);
}

.stat-card:hover {
  transform: translateY(-5px);
  background: rgba(0, 255, 136, 0.15);
  box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
}

.stat-label {
  color: #00ccff;
  font-size: 0.85em;
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-bottom: 10px;
}

.stat-value {
  font-size: 2.5em;
  color: #00ff88;
  font-weight: bold;
  text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
}

.button-group {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 15px;
  margin-bottom: 30px;
}

@media (max-width: 768px) {
  .button-group { grid-template-columns: 1fr; }
}

.btn {
  display: inline-block;
  padding: 15px 25px;
  background: linear-gradient(135deg, #00ff88, #00ccff);
  border: none;
  border-radius: 8px;
  color: #0a0e27;
  font-weight: bold;
  font-size: 1em;
  text-transform: uppercase;
  letter-spacing: 1px;
  cursor: pointer;
  transition: all 0.3s ease;
  box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
  text-decoration: none;
  text-align: center;
  position: relative;
  overflow: hidden;
}

.btn::before {
  content: '';
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle, rgba(255, 255, 255, 0.3) 0%, transparent 70%);
  transform: scale(0);
  transition: transform 0.6s ease-out;
}

.btn:hover::before {
  transform: scale(1);
}

.btn:hover {
  transform: translateY(-3px);
  box-shadow: 0 10px 40px rgba(0, 255, 136, 0.5);
}

.btn:active {
  transform: translateY(-1px);
}

.section {
  margin-bottom: 30px;
  animation: slideUp 0.7s ease-out;
}

.section-title {
  color: #00ff88;
  font-size: 1.5em;
  margin-bottom: 20px;
  padding-bottom: 10px;
  border-bottom: 2px solid #00ccff;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.table-wrapper {
  background: rgba(0, 255, 136, 0.05);
  border: 2px solid #00ff88;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 0 20px rgba(0, 255, 136, 0.1);
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.95em;
}

thead {
  background: linear-gradient(90deg, rgba(0, 255, 136, 0.2), rgba(0, 204, 255, 0.2));
  border-bottom: 2px solid #00ff88;
}

th {
  padding: 15px;
  text-align: left;
  color: #00ff88;
  font-weight: bold;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

td {
  padding: 12px 15px;
  border-bottom: 1px solid rgba(0, 255, 136, 0.2);
  color: #e0e0e0;
}

tbody tr {
  transition: all 0.3s ease;
}

tbody tr:hover {
  background: rgba(0, 255, 136, 0.1);
  box-shadow: inset 0 0 10px rgba(0, 255, 136, 0.05);
}

.threat-high {
  color: #ff4444;
  font-weight: bold;
}

.threat-medium {
  color: #ffaa44;
  font-weight: bold;
}

.threat-low {
  color: #00ff88;
}

.status-indicator {
  display: inline-block;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #00ff88;
  animation: pulse 2s infinite;
  margin-right: 8px;
}

@keyframes pulse {
  0%, 100% { opacity: 0.6; box-shadow: 0 0 0 0 rgba(0, 255, 136, 0.7); }
  50% { opacity: 1; box-shadow: 0 0 0 10px rgba(0, 255, 136, 0); }
}

@media (max-width: 768px) {
  .container {
    padding: 25px;
  }
  
  .header h1 {
    font-size: 2em;
  }
  
  .stats-grid {
    grid-template-columns: 1fr;
  }
  
  table {
    font-size: 0.85em;
  }
  
  th, td {
    padding: 10px;
  }
}
</style>
</head>
<body>

<div class="container">
  <div class="header">
    <h1>SOC CORRELATION LAB</h1>
    <p><span class="status-indicator"></span>Snort & Wazuh Integration Dashboard</p>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Snort Events</div>
      <div class="stat-value">{{ snort_total }}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Wazuh Events</div>
      <div class="stat-value">{{ wazuh_total }}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Total Correlation</div>
      <div class="stat-value">{{ snort_total + wazuh_total }}</div>
    </div>
  </div>

  <div class="button-group">
    <a class="btn" href="/refresh">REFRESH DATA</a>
    <a class="btn" href="/export/html">EXPORT REPORT</a>
  </div>

  <div class="section">
    <div class="section-title">Correlation Results by IP</div>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Source IP</th>
            <th>Snort Events</th>
            <th>Wazuh Events</th>
            <th>Correlation Level</th>
            <th>Threat Level</th>
          </tr>
        </thead>
        <tbody>
          {% for r in results %}
          <tr>
            <td>{{ r.ip }}</td>
            <td>{{ r.snort }}</td>
            <td>{{ r.wazuh }}</td>
            <td>{{ r.level }}</td>
            <td>
              {% if r.level >= 50 %}
                <span class="threat-high">🔴 CRITICAL</span>
              {% elif r.level >= 20 %}
                <span class="threat-medium">🟠 HIGH</span>
              {% else %}
                <span class="threat-low">🟢 LOW</span>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>

</body>
</html>
"""


# ========= GENERATION RAPPORT HTML (PRO SOC) =========
def build_report_html(snort_total: int, wazuh_total: int, results: list) -> str:
    """
    Rapport professionnel SOC Cybersecurity avec design moderne.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    rows = ""
    critical_count = 0
    high_count = 0
    low_count = 0
    
    for r in results:
        level = r['level']
        if level >= 50:
            threat = '<span class="threat-critical">🔴 CRITICAL</span>'
            critical_count += 1
        elif level >= 20:
            threat = '<span class="threat-high">🟠 HIGH</span>'
            high_count += 1
        else:
            threat = '<span class="threat-low">🟢 LOW</span>'
            low_count += 1
            
        rows += f"""
        <tr class="row-data">
          <td><code>{r['ip']}</code></td>
          <td><span class="badge badge-snort">{r['snort']}</span></td>
          <td><span class="badge badge-wazuh">{r['wazuh']}</span></td>
          <td><strong>{r['level']}</strong></td>
          <td>{threat}</td>
        </tr>
        """

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC Correlation Report - Snort & Wazuh</title>
  <style>
    * {{
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }}

    body {{
      font-family: 'Courier New', 'JetBrains Mono', monospace;
      background: linear-gradient(135deg, #0a0e27 0%, #1a1a3e 50%, #0f1a2e 100%);
      color: #e0e0e0;
      padding: 40px 20px;
    }}

    .report-container {{
      max-width: 1200px;
      margin: 0 auto;
      background: rgba(15, 26, 46, 0.95);
      backdrop-filter: blur(10px);
      border: 2px solid #00ff88;
      border-radius: 12px;
      padding: 50px;
      box-shadow: 0 0 50px rgba(0, 255, 136, 0.3), inset 0 0 20px rgba(0, 255, 136, 0.05);
    }}

    .report-header {{
      text-align: center;
      margin-bottom: 50px;
      border-bottom: 3px solid #00ff88;
      padding-bottom: 30px;
    }}

    .report-title {{
      font-size: 3em;
      background: linear-gradient(45deg, #00ff88, #00ccff, #00ff88);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      text-shadow: 0 0 30px rgba(0, 255, 136, 0.5);
      margin-bottom: 10px;
      letter-spacing: 2px;
    }}

    .report-subtitle {{
      color: #00ccff;
      font-size: 1.2em;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}

    .metadata {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 20px;
      margin-bottom: 40px;
      padding: 30px;
      background: rgba(0, 255, 136, 0.05);
      border: 1px solid rgba(0, 255, 136, 0.2);
      border-radius: 8px;
    }}

    .meta-item {{
      background: rgba(0, 204, 255, 0.05);
      padding: 20px;
      border-left: 3px solid #00ccff;
      border-radius: 4px;
    }}

    .meta-label {{
      color: #00ff88;
      font-size: 0.85em;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 8px;
    }}

    .meta-value {{
      font-size: 1.8em;
      color: #00ccff;
      font-weight: bold;
    }}

    .timestamp {{
      color: #00ccff;
      font-size: 0.9em;
      margin-top: 20px;
    }}

    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px;
      margin-bottom: 40px;
    }}

    .summary-card {{
      background: rgba(0, 255, 136, 0.05);
      border: 2px solid #00ff88;
      border-radius: 8px;
      padding: 25px;
      text-align: center;
      transition: all 0.3s ease;
    }}

    .summary-card:hover {{
      background: rgba(0, 255, 136, 0.15);
      box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
    }}

    .summary-label {{
      color: #00ccff;
      font-size: 0.9em;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 10px;
    }}

    .summary-value {{
      font-size: 2.5em;
      color: #00ff88;
      font-weight: bold;
      text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
    }}

    .threat-stats {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 15px;
      margin-bottom: 40px;
    }}

    .threat-item {{
      padding: 15px;
      border-radius: 6px;
      text-align: center;
    }}

    .threat-critical-bg {{
      background: rgba(255, 68, 68, 0.15);
      border: 1px solid #ff4444;
    }}

    .threat-high-bg {{
      background: rgba(255, 170, 68, 0.15);
      border: 1px solid #ffaa44;
    }}

    .threat-low-bg {{
      background: rgba(0, 255, 136, 0.15);
      border: 1px solid #00ff88;
    }}

    .threat-label {{
      font-size: 0.85em;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 5px;
    }}

    .threat-count {{
      font-size: 2em;
      font-weight: bold;
    }}

    .section {{
      margin-bottom: 40px;
    }}

    .section-title {{
      color: #00ff88;
      font-size: 1.8em;
      margin-bottom: 25px;
      padding-bottom: 15px;
      border-bottom: 2px solid #00ccff;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}

    .table-wrapper {{
      background: rgba(0, 255, 136, 0.05);
      border: 2px solid #00ff88;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 0 20px rgba(0, 255, 136, 0.1);
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.95em;
    }}

    thead {{
      background: linear-gradient(90deg, rgba(0, 255, 136, 0.2), rgba(0, 204, 255, 0.2));
      border-bottom: 2px solid #00ff88;
    }}

    th {{
      padding: 18px;
      text-align: left;
      color: #00ff88;
      font-weight: bold;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    td {{
      padding: 14px 18px;
      border-bottom: 1px solid rgba(0, 255, 136, 0.2);
      color: #e0e0e0;
    }}

    tbody tr {{
      transition: all 0.3s ease;
    }}

    tbody tr:hover {{
      background: rgba(0, 255, 136, 0.1);
      box-shadow: inset 0 0 10px rgba(0, 255, 136, 0.05);
    }}

    .badge {{
      display: inline-block;
      padding: 6px 12px;
      border-radius: 4px;
      font-weight: bold;
      font-size: 0.85em;
    }}

    .badge-snort {{
      background: rgba(0, 204, 255, 0.2);
      color: #00ccff;
      border: 1px solid #00ccff;
    }}

    .badge-wazuh {{
      background: rgba(0, 255, 136, 0.2);
      color: #00ff88;
      border: 1px solid #00ff88;
    }}

    .threat-critical {{
      color: #ff4444;
      font-weight: bold;
    }}

    .threat-high {{
      color: #ffaa44;
      font-weight: bold;
    }}

    .threat-low {{
      color: #00ff88;
      font-weight: bold;
    }}

    code {{
      background: rgba(0, 0, 0, 0.3);
      padding: 4px 8px;
      border-radius: 3px;
      color: #00ff88;
    }}

    .footer {{
      margin-top: 50px;
      padding-top: 30px;
      border-top: 1px solid rgba(0, 255, 136, 0.2);
      text-align: center;
      color: #00ccff;
      font-size: 0.9em;
    }}

    .footer-text {{
      margin-bottom: 10px;
    }}

    .status-good {{
      color: #00ff88;
    }}

    .status-warning {{
      color: #ffaa44;
    }}

    .status-critical {{
      color: #ff4444;
    }}

    @media print {{
      body {{
        background: white;
      }}
      .report-container {{
        background: white;
        border: none;
        box-shadow: none;
        padding: 30px;
      }}
      .report-title {{
        color: #000;
      }}
    }}
  </style>
</head>
<body>

<div class="report-container">
  
  <div class="report-header">
    <div class="report-title">SOC CORRELATION REPORT</div>
    <div class="report-subtitle">Snort & Wazuh Integration Analysis</div>
  </div>

  <div class="metadata">
    <div class="meta-item">
      <div class="meta-label">📅 Report Generated</div>
      <div class="meta-value" style="font-size: 1.2em;">{now}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Analysis Period</div>
      <div class="meta-value">Current Session</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Status</div>
      <div class="meta-value status-good">Active</div>
    </div>
  </div>

  <div class="summary-grid">
    <div class="summary-card">
      <div class="summary-label">Total Snort Alerts</div>
      <div class="summary-value">{snort_total}</div>
    </div>
    <div class="summary-card">
      <div class="summary-label">Total Wazuh Events</div>
      <div class="summary-value">{wazuh_total}</div>
    </div>
    <div class="summary-card">
      <div class="summary-label">Combined Correlation</div>
      <div class="summary-value">{snort_total + wazuh_total}</div>
    </div>
  </div>

  <div class="threat-stats">
    <div class="threat-item threat-critical-bg">
      <div class="threat-label">Critical Threats</div>
      <div class="threat-count">{critical_count}</div>
    </div>
    <div class="threat-item threat-high-bg">
      <div class="threat-label">High Priority</div>
      <div class="threat-count">{high_count}</div>
    </div>
    <div class="threat-item threat-low-bg">
      <div class="threat-label">Low Risk</div>
      <div class="threat-count">{low_count}</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Detailed Correlation Analysis</div>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Source IP Address</th>
            <th>Snort Events</th>
            <th>Wazuh Events</th>
            <th>Correlation Level</th>
            <th>Threat Assessment</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>
  </div>

  <div class="footer">
    <div class="footer-text">🔒 Confidential - SOC Internal Use Only</div>
    <div class="footer-text">Generated by SOC Correlation Lab v1.0</div>
    <div class="footer-text">Snort & Wazuh Integration Platform</div>
  </div>

</div>

</body>
</html>
"""


# ========= ROUTES =========
@app.route("/")
def home():
    snort_total, wazuh_total, results = compute_results()
    return render_template_string(PAGE_HTML, snort_total=snort_total, wazuh_total=wazuh_total, results=results)

@app.route("/refresh")
def refresh():
    return home()

@app.route("/export/html")
def export_html():
    snort_total, wazuh_total, results = compute_results()

    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = f"rapport_soc_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(REPORT_DIR, filename)

    html = build_report_html(snort_total, wazuh_total, results)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return send_file(filepath, as_attachment=True)


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)

