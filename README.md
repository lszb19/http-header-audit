# HTTP Security Headers Auditor

A robust Python tool to audit HTTP security headers of multiple websites using a strict, OWASP-aligned policy. It generates a detailed, color-coded Excel report of the findings.

## Features

-   **Bulk Auditing**: Scans a list of domains from a file.
-   **Excel Reporting**: Generates a styled `.xlsx` report with:
    -   **Green**: Header present and secure.
    -   **Red**: Header missing.
    -   **Yellow**: Header present but misconfigured (with specific error details).
-   **Strict Security Checks**:
    -   **HSTS**: Enforces `max-age` ≥ 120 days.
    -   **CSP**: Flags `unsafe-inline` (unless nonce/hash is present) and `unsafe-eval`. Ignores `wasm-unsafe-eval`.
    -   **X-Frame-Options**: Strictly enforced (must be `DENY` or `SAMEORIGIN`), regardless of CSP.
-   **Visual Progress**: Includes a progress bar for long scans.
-   **Modern User-Agent**: Uses a modern Chrome User-Agent to ensure servers respond with their latest security policies.

## Installation

Ensure you have Python 3 installed.

1.  **Install Dependencies**:
    ```bash
    pip install openpyxl tqdm
    ```
    *Note: `tqdm` is optional but recommended for the progress bar.*

## Usage

1.  **Prepare your input file** (e.g., `hosts.txt`):
    ```text
    google.com
    github.com
    example.com
    ```
    *The script automatically prepends `https://` if missing.*

2.  **Run the script**:
    ```bash
    python secure_headers.py hosts.txt report.xlsx
    ```

3.  **View Results**: Open `report.xlsx` to view the audit grid.

## Security Rules Logic

| Header | Rule | Misconfiguration Trigger |
| :--- | :--- | :--- |
| **Strict-Transport-Security** | `max-age` ≥ 120 days | `max-age` < 10,368,000s or missing header. (Missing `includeSubDomains` is allowed). |
| **Content-Security-Policy** | No unsafe directives | `unsafe-eval` (strict). `unsafe-inline` (allowed ONLY if nonce/hash is present). |
| **X-Frame-Options** | Anti-Clickjacking | Value is not `DENY` or `SAMEORIGIN`. |
| **X-Content-Type-Options** | MIME Sniffing | Value is not `nosniff`. |
| **Referrer-Policy** | Privacy | Value contains `unsafe-url`. |

## Disclaimer
This tool is for educational and authorized testing purposes only. Ensure you have permission to scan the target domains.