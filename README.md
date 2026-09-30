

PortRadar is a single-file TCP port status checker built with pure Python
and a cyber-themed HTML interface. It runs as a local website and needs no
external libraries.

 Features
- Scan common ports, a custom range, or a custom port list
- Detects open, closed and filtered ports
- Banner grabbing and service identification
- Risk labels (HIGH / MEDIUM / LOW) for commonly exposed services
- Animated live radar view with a real-time progress bar
- Export scan results as JSON

 Disclaimer
For educational use only. Scan only systems you own or have
written permission to test.

 Project Structure

```
PortRadar/
├── app.py            # Complete project: backend server + web UI
├── README.md         # Project documentation
└── screenshot.png    # Screenshot of the radar interface (optional)
```

 Inside `app.py`

```
app.py
├── Configuration      → host, port, scan limits, common ports list
├── Service & Risk DB  → port-to-service names and risk notes
├── check_port()       → TCP connect check (open / closed / filtered) + banner grab
├── parse_ports()      → validates common / range / custom port input
├── run_job()          → multithreaded scan running in the background
├── Handler            → HTTP server with the /api/scan and /api/status endpoints
└── PAGE               → HTML, CSS and JavaScript for the radar UI
```

 How it works

```
Browser (HTML/CSS/JS)  ──POST /api/scan──▶  Python server (http.server)
        ▲                                          │
        │                                   Thread pool (100 workers)
        └──── GET /api/status (polling) ◀── socket TCP checks
```
