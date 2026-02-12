# sqlmap Browser Scanner

SQL injection scanner that runs in your browser via Burp proxy. **No Python on the visiting machine.** All requests originate from your browser.

## Setup

1. **Configure Burp** — Proxy → Options → Match and Replace → Add  
   - Type: Response header | Match: empty | Replace: `Access-Control-Allow-Origin: *`

2. **Set browser proxy** — Point to Burp (e.g. 127.0.0.1:8080)

## How to start

| Method | Command / action |
|--------|------------------|
| **With server** | `python sqlmapapi.py -s -H 0.0.0.0 -p 80` → open `http://YOUR_IP/` from your browser |
| **Standalone** | Double‑click `index.html` (no server needed) |

## Usage

Enter target URL, optional POST data and cookie, choose technique, click Scan. Inputs are remembered across sessions.
