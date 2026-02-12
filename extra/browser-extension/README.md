# sqlmap Browser Extension

A Chrome extension that runs SQL injection detection **entirely in your browser**. All HTTP requests to the target originate from your machine—no Python, no server, no proxy required.

## Use Case

When you cannot install Python or run sqlmap on your machine, but you can use a web browser. The extension makes requests directly from the browser (bypassing CORS via extension permissions), so the traffic comes from your IP.

## Installation

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle top-right)
3. Click **Load unpacked**
4. Select the `extra/browser-extension` folder from this sqlmap directory

## Usage

1. Click the extension icon
2. Enter a target URL with query parameters (e.g. `https://example.com/page?id=1`)
   - Or click **Use current tab** to scan the page you're on
3. Choose technique: All, Boolean blind, Time-based, or Error-based
4. Click **Scan**

The extension will:

- Parse URL parameters
- Send requests with SQL injection payloads **from your browser**
- Compare responses (boolean blind), measure timing (time-based), or look for errors (error-based)
- Report any suspected vulnerabilities

## Limitations

- **Simpler than full sqlmap**: Implements basic detection only (boolean blind, time-based, error-based). No full exploitation, enumeration, or data extraction.
- **GET and POST**: Supports both query string and POST body parameters.
- **Single-origin**: Scans one URL at a time.
- **Chrome only**: Built for Chromium-based browsers (Chrome, Edge, Brave). A Firefox port would need a separate WebExtension.

## Security Note

The extension requests `<all_urls>` permission so it can send requests to any target. Only install from a trusted source. Use only on systems you are authorized to test.
