# HTTP Security Headers Auditor

A Python tool to audit HTTP security headers of multiple websites. Generates a color-coded Excel report with detailed findings.

## Features

- **Bulk Auditing**: Scans domains from a text file
- **Protocol Fallback**: Tries HTTPS first, falls back to HTTP for HTTP-only hosts
- **Unreachable Host Tracking**: Includes failed connections in output
- **Excel Report** with color coding:
  - 🟢 **Green**: Header present and secure
  - 🔴 **Red**: Header missing
  - 🟡 **Yellow**: Header misconfigured
- **Progress Bar**: Visual progress for long scans

## Security Checks

| Header | Requirement | Misconfiguration |
|--------|-------------|------------------|
| **Strict-Transport-Security** | `max-age` ≥ 120 days | Value too low or missing |
| **Content-Security-Policy** | No unsafe directives | `unsafe-eval` always flagged; `unsafe-inline` flagged unless nonce/hash present |
| **X-Frame-Options** | Anti-Clickjacking | Not `DENY` or `SAMEORIGIN` |
| **X-Content-Type-Options** | MIME Sniffing | Not `nosniff` |
| **Referrer-Policy** | Privacy | Contains `unsafe-url` |
| **Permissions-Policy** | Feature control | Missing |

## Installation

```bash
# Using uv (recommended)
uv run --with requests,openpyxl,tqdm secure_headers.py hosts.txt output.xlsx

# Or install dependencies manually
pip install requests openpyxl tqdm
```

## Usage

1. **Create a hosts file** (`hosts.txt`):
   ```text
   google.com
   github.com
   example.com
   ```

2. **Run the scan**:
   ```bash
   uv run --with requests,openpyxl,tqdm secure_headers.py hosts.txt report.xlsx
   ```

3. **View results** in `report.xlsx`

## Output Format

| Input Domain | Final URL | HSTS | CSP | X-Frame-Options | ... |
|--------------|-----------|------|-----|-----------------|-----|
| example.com | https://example.com/ | OK | Missing | OK | ... |
| internal.example.com | internal.example.com | Connection Failed | Connection Failed | ... |

## Disclaimer

For authorized testing only. Ensure you have permission to scan target domains.