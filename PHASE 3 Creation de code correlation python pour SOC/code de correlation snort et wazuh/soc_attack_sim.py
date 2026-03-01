from flask import Flask, request, render_template_string
import subprocess, time, socket
import requests
import paramiko

app = Flask(__name__)

HTML = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Attack Simulation Lab</title>
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
  max-width: 1200px;
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

.warning-box {
  background: rgba(255, 100, 0, 0.1);
  border-left: 4px solid #ff6400;
  border-radius: 4px;
  padding: 15px;
  margin-bottom: 30px;
  color: #ffaa44;
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 0.8; }
  50% { opacity: 1; }
}

.warning-box::before {
  content: "";
  font-weight: bold;
  margin-right: 5px;
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 25px;
  margin-bottom: 30px;
}

@media (max-width: 768px) {
  .form-grid { grid-template-columns: 1fr; }
}

.form-group {
  animation: slideUp 0.6s ease-out;
}

@keyframes slideUp {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
}

label {
  display: block;
  margin-bottom: 10px;
  color: #00ff88;
  font-weight: bold;
  font-size: 0.95em;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

input[type="text"],
input[type="number"],
select {
  width: 100%;
  padding: 12px 15px;
  background: rgba(0, 255, 136, 0.05);
  border: 2px solid #00ff88;
  border-radius: 6px;
  color: #e0e0e0;
  font-family: inherit;
  font-size: 1em;
  transition: all 0.3s ease;
}

input[type="text"]:focus,
input[type="number"]:focus,
select:focus {
  outline: none;
  background: rgba(0, 255, 136, 0.15);
  border-color: #00ccff;
  box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
}

input[type="text"]::placeholder {
  color: #00ff8844;
}

.checkbox-group {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 20px 0;
  animation: slideUp 0.7s ease-out;
}

input[type="checkbox"] {
  width: 22px;
  height: 22px;
  cursor: pointer;
  accent-color: #00ff88;
}

.checkbox-group label {
  margin: 0;
  color: #e0e0e0;
  text-transform: none;
  letter-spacing: normal;
}

.button-group {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 15px;
  margin-top: 30px;
}

@media (max-width: 768px) {
  .button-group { grid-template-columns: 1fr; }
}

button {
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
  position: relative;
  overflow: hidden;
}

button::before {
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

button:hover::before {
  transform: scale(1);
}

button:hover {
  transform: translateY(-3px);
  box-shadow: 0 10px 40px rgba(0, 255, 136, 0.5);
}

button:active {
  transform: translateY(-1px);
}

.output-section {
  margin-top: 40px;
  animation: slideUp 0.8s ease-out;
}

.output-label {
  color: #00ff88;
  font-weight: bold;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 15px;
  display: block;
}

.output-box {
  background: #0a0e27;
  border: 2px solid #00ccff;
  border-radius: 8px;
  padding: 20px;
  color: #00ff88;
  font-size: 0.95em;
  line-height: 1.6;
  white-space: pre-wrap;
  word-wrap: break-word;
  max-height: 400px;
  overflow-y: auto;
  box-shadow: inset 0 0 20px rgba(0, 204, 255, 0.1), 0 0 30px rgba(0, 204, 255, 0.2);
  position: relative;
}

.output-box::before {
  content: '> _';
  position: absolute;
  top: 10px;
  right: 15px;
  color: #00ccff;
  opacity: 0.5;
  animation: blink 1s infinite;
}

@keyframes blink {
  0%, 49%, 100% { opacity: 0.5; }
  50%, 99% { opacity: 1; }
}

.output-box::-webkit-scrollbar {
  width: 8px;
}

.output-box::-webkit-scrollbar-track {
  background: rgba(0, 255, 136, 0.05);
  border-radius: 4px;
}

.output-box::-webkit-scrollbar-thumb {
  background: #00ff88;
  border-radius: 4px;
}

.output-box::-webkit-scrollbar-thumb:hover {
  background: #00ccff;
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

@media (max-width: 768px) {
  .container {
    padding: 25px;
  }
  
  .header h1 {
    font-size: 2em;
  }
  
  .form-grid {
    gap: 15px;
  }
  
  button {
    padding: 12px 20px;
    font-size: 0.9em;
  }
}
</style>
</head>
<body>

<div class="container">
  <div class="header">
    <h1>SOC ATTACK SIMULATION LAB</h1>
    <p><span class="status-indicator"></span>Active Defense Training Suite</p>
  </div>

  <div class="warning-box">
    Générateur de trafic détectable (Snort/Wazuh). Aucun exploit réel. Usage laboratoire autorisé uniquement.
  </div>

  <form method="post">
    <div class="form-grid">
      <div class="form-group">
        <label>IP Victime (Nginx/SSH)</label>
        <input type="text" name="victim_ip" value="{{ victim_ip }}" placeholder="192.168.1.x" required>
      </div>

      <div class="form-group">
        <label>Ports à tester</label>
        <input type="text" name="ports" value="{{ ports }}" placeholder="22,80,443,21,25">
      </div>

      <div class="form-group">
        <label>Intensité / Durée</label>
        <select name="level">
          <option value="low">LOW - Trafic léger</option>
          <option value="medium" selected>MEDIUM - Modéré</option>
          <option value="high">HIGH - Agressif</option>
        </select>
      </div>
    </div>

    <div class="checkbox-group">
      <input type="checkbox" name="auth" id="auth-check" required>
      <label for="auth-check">Je certifie que j'ai l'autorisation d'effectuer ce test (LAB)</label>
    </div>

    <div class="button-group">
      <button name="action" value="icmp" type="submit">
        ICMP Ping Burst
      </button>
      <button name="action" value="http" type="submit">
        HTTP Burst
      </button>
      <button name="action" value="ssh" type="submit">
        SSH Failed Logins
      </button>
      <button name="action" value="scan" type="submit">
        Mini TCP Scan
      </button>
    </div>
  </form>

  <div class="output-section">
    <label class="output-label">Résultat / Output</label>
    <div class="output-box">{{ output }}</div>
  </div>
</div>

</body>
</html>
"""

def intensity(level: str):
    if level == "low":
        return {"ping_count": 5, "http_count": 10, "ssh_count": 3, "timeout": 1.0}
    if level == "high":
        return {"ping_count": 30, "http_count": 80, "ssh_count": 15, "timeout": 0.5}
    return {"ping_count": 15, "http_count": 40, "ssh_count": 8, "timeout": 0.8}

def icmp_ping_burst(ip: str, count: int):
    # Ping classique (ICMP) -> très visible côté Snort (règle ICMP)
    cmd = ["ping", "-c", str(count), ip]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout + p.stderr

def http_burst(ip: str, count: int, timeout: float):
    # Requêtes HTTP vers Nginx -> Snort (HTTP) + logs Nginx -> Wazuh
    url = f"http://{ip}/"
    out = []
    headers = {"User-Agent": "SOC-LAB-TrafficGenerator/1.0"}
    for i in range(count):
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            out.append(f"[{i+1}/{count}] {r.status_code} {len(r.content)} bytes")
        except Exception as e:
            out.append(f"[{i+1}/{count}] ERROR: {e}")
        time.sleep(0.05)
    return "\n".join(out)

def ssh_failed_logins(ip: str, count: int, timeout: float):
    # Tentatives SSH avec faux identifiants -> Wazuh (auth.log) + Snort (règle SSH si tu la mets)
    out = []
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for i in range(count):
        try:
            client.connect(
                hostname=ip,
                port=22,
                username="fakeuser",
                password="WrongPassword123!",
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                allow_agent=False,
                look_for_keys=False
            )
            out.append(f"[{i+1}/{count}] Unexpected: logged in (check SSH config!)")
        except Exception as e:
            out.append(f"[{i+1}/{count}] Auth failed (expected): {type(e).__name__}")
        time.sleep(0.15)
    try:
        client.close()
    except:
        pass
    return "\n".join(out)

def mini_tcp_scan(ip: str, ports: list[int], timeout: float):
    # Scan léger "style nmap" (connect scan) sur une liste de ports
    # -> Snort règle "NMAP scan detected SYN" peut réagir si tu génères assez de tentatives
    out = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        try:
            code = s.connect_ex((ip, port))
            elapsed = (time.time() - start) * 1000
            if code == 0:
                out.append(f"Port {port}: OPEN ({elapsed:.1f} ms)")
            else:
                out.append(f"Port {port}: CLOSED/FILTERED ({elapsed:.1f} ms)")
        except Exception as e:
            out.append(f"Port {port}: ERROR {e}")
        finally:
            s.close()
        time.sleep(0.03)
    return "\n".join(out)

@app.route("/", methods=["GET", "POST"])
def index():
    output = "Choisis un bouton pour lancer un test."
    victim_ip = "192.168.1.129"
    ports = "22,80,443,21,25"

    if request.method == "POST":
        victim_ip = request.form.get("victim_ip", victim_ip).strip()
        ports = request.form.get("ports", ports).strip()
        level = request.form.get("level", "medium")
        action = request.form.get("action", "")

        conf = intensity(level)

        if action == "icmp":
            output = icmp_ping_burst(victim_ip, conf["ping_count"])
        elif action == "http":
            output = http_burst(victim_ip, conf["http_count"], conf["timeout"])
        elif action == "ssh":
            output = ssh_failed_logins(victim_ip, conf["ssh_count"], conf["timeout"])
        elif action == "scan":
            try:
                plist = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
                output = mini_tcp_scan(victim_ip, plist, conf["timeout"])
            except Exception as e:
                output = f"Ports invalides: {e}"
        else:
            output = "Action inconnue."

    return render_template_string(HTML, output=output, victim_ip=victim_ip, ports=ports)

if __name__ == "__main__":
    # écoute sur le réseau du lab
    app.run(host="0.0.0.0", port=5000, debug=False)
