"""
PORTRADAR - Port Status Checker (single file, standard library only)
Run:  python app.py
Open: http://127.0.0.1:8000

Use ONLY on systems you own or have written permission to test.
"""
import json
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HOST, PORT = "127.0.0.1", 8000
MAX_PORTS = 2000  # safety limit per scan

COMMON_PORTS = [20, 21, 22, 23, 25, 53, 67, 80, 110, 123, 135, 139, 143, 161,
                389, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 3000,
                3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8443, 9200,
                27017]

SERVICES = {20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
            135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
            389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
            587: "SMTP-Submit", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
            1521: "Oracle DB", 2049: "NFS", 3000: "Dev Server",
            3306: "MySQL", 3389: "RDP", 5000: "Flask/Dev", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"}

# Simple risk notes shown when a port is OPEN (learning aid)
RISK = {21: ("HIGH", "FTP sends credentials in plain text."),
        23: ("HIGH", "Telnet is unencrypted. Use SSH instead."),
        135: ("MEDIUM", "MS-RPC is often abused for lateral movement."),
        139: ("MEDIUM", "NetBIOS can leak host information."),
        445: ("HIGH", "SMB exposure is a common ransomware entry point."),
        3389: ("HIGH", "RDP is a top brute-force target."),
        5900: ("HIGH", "VNC is often weakly protected."),
        1433: ("MEDIUM", "Database ports should not be public."),
        3306: ("MEDIUM", "Database ports should not be public."),
        5432: ("MEDIUM", "Database ports should not be public."),
        6379: ("HIGH", "Redis is often exposed without authentication."),
        27017: ("HIGH", "MongoDB is often exposed without authentication."),
        9200: ("MEDIUM", "Elasticsearch should not be public."),
        161: ("MEDIUM", "SNMP default community strings leak data."),
        80: ("LOW", "Unencrypted web traffic. Prefer HTTPS."),
        22: ("LOW", "Make sure key-based login and no root login.")}

JOBS = {}
LOCK = threading.Lock()


def service_name(port):
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "Unknown"


def grab_banner(sock, port):
    try:
        sock.settimeout(0.8)
        if port in (80, 8000, 8080, 3000, 5000):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(120)
        text = data.decode("utf-8", "ignore").strip().splitlines()
        return text[0][:100] if text else ""
    except OSError:
        return ""


def check_port(ip, port, timeout):
    start = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        latency = round((time.time() - start) * 1000, 1)
        banner = grab_banner(s, port)
        s.close()
        status = "open"
    except ConnectionRefusedError:
        latency, banner, status = round((time.time() - start) * 1000, 1), "", "closed"
    except OSError:  # timeout / unreachable = filtered
        latency, banner, status = None, "", "filtered"
    risk = RISK.get(port) if status == "open" else None
    return {"port": port, "status": status, "service": service_name(port),
            "latency": latency, "banner": banner,
            "risk": risk[0] if risk else "", "note": risk[1] if risk else ""}


def parse_ports(data):
    mode = data.get("mode", "common")
    if mode == "common":
        return COMMON_PORTS[:]
    if mode == "range":
        a, b = int(data.get("start", 1)), int(data.get("end", 1024))
        if a > b:
            a, b = b, a
        ports = list(range(a, b + 1))
    else:
        ports = sorted({int(p) for p in str(data.get("ports", "")).replace(" ", "").split(",") if p})
    if not ports:
        raise ValueError("No ports given.")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"Maximum {MAX_PORTS} ports per scan.")
    return ports


def run_job(job_id, ip, ports, timeout):
    job = JOBS[job_id]
    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = [pool.submit(check_port, ip, p, timeout) for p in ports]
        for f in as_completed(futures):
            res = f.result()
            with LOCK:
                job["done"] += 1
                job["counts"][res["status"]] += 1
                if res["status"] == "open":
                    job["open"].append(res)
    with LOCK:
        job["open"].sort(key=lambda r: r["port"])
        job["finished"] = True
        job["elapsed"] = round(time.time() - job["started"], 2)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif url.path == "/api/status":
            job_id = parse_qs(url.query).get("id", [""])[0]
            with LOCK:
                job = JOBS.get(job_id)
                if not job:
                    return self.send_json({"error": "Unknown job"}, 404)
                self.send_json(job)
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        if self.path != "/api/scan":
            return self.send_json({"error": "Not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or b"{}")
            target = str(data.get("host", "")).strip()
            if not target:
                raise ValueError("Enter a host or IP address.")
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                raise ValueError("Could not resolve that host.")
            ports = parse_ports(data)
            timeout = min(max(float(data.get("timeout", 1.0)), 0.2), 5.0)
        except (ValueError, json.JSONDecodeError) as e:
            return self.send_json({"error": str(e)}, 400)

        job_id = uuid.uuid4().hex[:10]
        JOBS[job_id] = {"id": job_id, "host": target, "ip": ip,
                        "total": len(ports), "done": 0, "finished": False,
                        "counts": {"open": 0, "closed": 0, "filtered": 0},
                        "open": [], "started": time.time(), "elapsed": 0}
        threading.Thread(target=run_job, args=(job_id, ip, ports, timeout),
                         daemon=True).start()
        self.send_json({"id": job_id})


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PortRadar - Port Status Checker</title>
<style>
:root{--bg:#050b10;--panel:#0a1620;--line:#12303f;--g:#00ff9c;--c:#22d3ee;--r:#ff4d6d;--y:#ffd166;--t:#cfeee6;--m:#6b8f8a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--t);font-family:Consolas,"Courier New",monospace;
background-image:linear-gradient(rgba(0,255,156,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,156,.04) 1px,transparent 1px);
background-size:36px 36px;min-height:100vh}
header{padding:22px 28px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
h1{margin:0;font-size:26px;letter-spacing:4px;color:var(--g);text-shadow:0 0 12px rgba(0,255,156,.6)}
h1 span{color:var(--c)}
.tag{color:var(--m);font-size:12px}
main{max-width:1200px;margin:0 auto;padding:24px;display:grid;grid-template-columns:340px 1fr;gap:24px}
@media(max-width:900px){main{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px}
label{display:block;font-size:11px;color:var(--m);margin:12px 0 4px;letter-spacing:2px;text-transform:uppercase}
input,select{width:100%;padding:10px;background:#06111a;border:1px solid var(--line);color:var(--g);border-radius:6px;font:inherit}
input:focus,select:focus{outline:none;border-color:var(--g);box-shadow:0 0 8px rgba(0,255,156,.35)}
.row{display:flex;gap:8px}
button{width:100%;margin-top:18px;padding:12px;background:transparent;color:var(--g);border:1px solid var(--g);border-radius:6px;font:inherit;letter-spacing:3px;cursor:pointer;transition:.2s}
button:hover:not(:disabled){background:var(--g);color:#001a10;box-shadow:0 0 18px rgba(0,255,156,.6)}
button:disabled{opacity:.4;cursor:not-allowed}
button.alt{margin-top:10px;color:var(--c);border-color:var(--c);font-size:12px;padding:8px}
button.alt:hover:not(:disabled){background:var(--c);color:#00171c;box-shadow:0 0 14px rgba(34,211,238,.5)}
.warn{font-size:11px;color:var(--y);margin-top:14px;line-height:1.5;border-left:2px solid var(--y);padding-left:8px}
.err{color:var(--r);font-size:13px;margin-top:10px;min-height:16px}
.radarwrap{display:flex;justify-content:center;margin-bottom:16px}
.radar{position:relative;width:300px;height:300px;border-radius:50%;border:1px solid var(--g);
background:radial-gradient(circle,transparent 0 24%,rgba(0,255,156,.18) 24.5%,transparent 25% 49%,rgba(0,255,156,.18) 49.5%,transparent 50% 74%,rgba(0,255,156,.18) 74.5%,transparent 75%),
linear-gradient(rgba(0,255,156,.15),rgba(0,255,156,.15)) center/1px 100% no-repeat,linear-gradient(rgba(0,255,156,.15),rgba(0,255,156,.15)) center/100% 1px no-repeat,#04100d;
box-shadow:0 0 30px rgba(0,255,156,.25) inset,0 0 25px rgba(0,255,156,.15);overflow:hidden}
.sweep{position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,rgba(0,255,156,.55),transparent 25%);animation:spin 2.4s linear infinite;display:none}
.scanning .sweep{display:block}
@keyframes spin{to{transform:rotate(360deg)}}
.blip{position:absolute;width:10px;height:10px;border-radius:50%;background:var(--g);box-shadow:0 0 10px var(--g);transform:translate(-50%,-50%);animation:pulse 1.6s infinite}
.blip.HIGH{background:var(--r);box-shadow:0 0 10px var(--r)}
.blip.MEDIUM{background:var(--y);box-shadow:0 0 10px var(--y)}
@keyframes pulse{50%{transform:translate(-50%,-50%) scale(1.6);opacity:.6}}
.bar{height:8px;background:#06111a;border:1px solid var(--line);border-radius:5px;overflow:hidden;margin-bottom:6px}
.bar div{height:100%;width:0;background:linear-gradient(90deg,var(--c),var(--g));transition:width .3s}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}
.stat{background:#06111a;border:1px solid var(--line);border-radius:8px;padding:10px;text-align:center}
.stat b{display:block;font-size:22px}
.stat small{color:var(--m);font-size:10px;letter-spacing:2px}
.o b{color:var(--g)}.c b{color:var(--r)}.f b{color:var(--y)}.t b{color:var(--c)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{color:var(--m);text-align:left;font-size:11px;letter-spacing:2px;padding:8px;border-bottom:1px solid var(--line)}
td{padding:8px;border-bottom:1px solid #0d2230;vertical-align:top}
.pill{padding:2px 8px;border-radius:10px;font-size:11px;border:1px solid}
.pill.OPEN{color:var(--g);border-color:var(--g)}
.pill.HIGH{color:var(--r);border-color:var(--r)}
.pill.MEDIUM{color:var(--y);border-color:var(--y)}
.pill.LOW{color:var(--c);border-color:var(--c)}
.muted{color:var(--m)}
.tablewrap{overflow-x:auto}
</style>
</head>
<body>
<header>
  <h1>PORT<span>RADAR</span></h1>
  <div class="tag">// TCP PORT STATUS CHECKER &bull; PYTHON + HTML</div>
</header>
<main>
  <section class="panel">
    <label>Target host / IP</label>
    <input id="host" value="127.0.0.1" placeholder="example.com or 192.168.1.1">
    <label>Scan mode</label>
    <select id="mode">
      <option value="common">Common ports (fast)</option>
      <option value="range">Port range</option>
      <option value="custom">Custom list</option>
    </select>
    <div id="rangeBox" style="display:none">
      <label>Range</label>
      <div class="row"><input id="start" type="number" value="1" min="1" max="65535"><input id="end" type="number" value="1024" min="1" max="65535"></div>
    </div>
    <div id="customBox" style="display:none">
      <label>Ports (comma separated)</label>
      <input id="ports" value="22,80,443,8080">
    </div>
    <label>Timeout (seconds)</label>
    <input id="timeout" type="number" value="1" min="0.2" max="5" step="0.1">
    <button id="go">&#9654; START SCAN</button>
    <button class="alt" id="exp" disabled>EXPORT RESULT (JSON)</button>
    <div class="err" id="err"></div>
    <div class="warn">Scan only systems you own or have written permission to test. Unauthorized scanning may be illegal.</div>
  </section>

  <section>
    <div class="panel" id="radarPanel">
      <div class="radarwrap"><div class="radar" id="radar"><div class="sweep"></div></div></div>
      <div class="bar"><div id="bar"></div></div>
      <div class="muted" id="status">Ready. Configure a target and start a scan.</div>
      <div class="stats">
        <div class="stat o"><b id="sOpen">0</b><small>OPEN</small></div>
        <div class="stat c"><b id="sClosed">0</b><small>CLOSED</small></div>
        <div class="stat f"><b id="sFilt">0</b><small>FILTERED</small></div>
        <div class="stat t"><b id="sTime">0s</b><small>TIME</small></div>
      </div>
    </div>
    <div class="panel" style="margin-top:24px">
      <div class="tablewrap">
      <table>
        <thead><tr><th>PORT</th><th>STATUS</th><th>SERVICE</th><th>LATENCY</th><th>RISK</th><th>BANNER / NOTE</th></tr></thead>
        <tbody id="rows"><tr><td colspan="6" class="muted">No open ports yet.</td></tr></tbody>
      </table>
      </div>
    </div>
  </section>
</main>

<script>
const $ = id => document.getElementById(id);
let timer = null, lastResult = null;

$("mode").onchange = () => {
  $("rangeBox").style.display = $("mode").value === "range" ? "block" : "none";
  $("customBox").style.display = $("mode").value === "custom" ? "block" : "none";
};

function cell(tr, text, cls) {
  const td = document.createElement("td");
  if (cls) {
    const s = document.createElement("span");
    s.className = "pill " + cls; s.textContent = text; td.appendChild(s);
  } else td.textContent = text;
  tr.appendChild(td);
}

function render(job) {
  const pct = job.total ? Math.round(job.done / job.total * 100) : 0;
  $("bar").style.width = pct + "%";
  $("sOpen").textContent = job.counts.open;
  $("sClosed").textContent = job.counts.closed;
  $("sFilt").textContent = job.counts.filtered;
  $("sTime").textContent = job.finished ? job.elapsed + "s" : Math.round(Date.now() / 1000 - job.started) + "s";
  $("status").textContent = (job.finished ? "Scan complete" : "Scanning") +
    " " + job.host + " (" + job.ip + ") - " + job.done + "/" + job.total + " ports (" + pct + "%)";

  const rows = $("rows"); rows.innerHTML = "";
  if (!job.open.length) {
    rows.innerHTML = '<tr><td colspan="6" class="muted">No open ports found yet.</td></tr>';
  }
  const radar = $("radar");
  radar.querySelectorAll(".blip").forEach(b => b.remove());
  job.open.forEach(r => {
    const tr = document.createElement("tr");
    cell(tr, r.port); cell(tr, "OPEN", "OPEN"); cell(tr, r.service);
    cell(tr, r.latency !== null ? r.latency + " ms" : "-");
    if (r.risk) cell(tr, r.risk, r.risk); else cell(tr, "-");
    cell(tr, r.banner || r.note || "-");
    rows.appendChild(tr);

    // radar blip: angle from port number, distance from latency
    const ang = (r.port / 65535) * 2 * Math.PI;
    const dist = 25 + Math.min(r.latency || 0, 100) / 100 * 22;
    const b = document.createElement("div");
    b.className = "blip " + (r.risk === "HIGH" || r.risk === "MEDIUM" ? r.risk : "");
    b.style.left = (50 + Math.cos(ang) * dist) + "%";
    b.style.top = (50 + Math.sin(ang) * dist) + "%";
    b.title = "Port " + r.port + " (" + r.service + ")";
    radar.appendChild(b);
  });
}

async function poll(id) {
  try {
    const res = await fetch("/api/status?id=" + id);
    const job = await res.json();
    lastResult = job;
    render(job);
    if (job.finished) {
      clearInterval(timer);
      $("go").disabled = false; $("exp").disabled = false;
      $("radar").classList.remove("scanning");
    }
  } catch (e) {
    clearInterval(timer); $("go").disabled = false;
    $("err").textContent = "Lost connection to server.";
  }
}

$("go").onclick = async () => {
  $("err").textContent = "";
  const body = {
    host: $("host").value, mode: $("mode").value,
    start: $("start").value, end: $("end").value,
    ports: $("ports").value, timeout: $("timeout").value
  };
  $("go").disabled = true; $("exp").disabled = true;
  try {
    const res = await fetch("/api/scan", {method: "POST", body: JSON.stringify(body)});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Scan failed");
    $("radar").classList.add("scanning");
    timer = setInterval(() => poll(data.id), 400);
  } catch (e) {
    $("err").textContent = e.message;
    $("go").disabled = false;
  }
};

$("exp").onclick = () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], {type: "application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "portradar_" + lastResult.host + ".json";
  a.click();
};
</script>
</body>
</html>
"""

if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"PortRadar running at http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()