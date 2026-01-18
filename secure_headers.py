import sys
import urllib.request
import urllib.error
import urllib.parse
import ssl
import re

# Configuration
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
TIMEOUT_SECONDS = 10
HSTS_MIN_AGE = 10368000 # 120 days

# Security Check Configuration
SEC_HEADERS = {
'Strict-Transport-Security': 'error',
'Content-Security-Policy': 'warning',
'X-Frame-Options': 'warning',
'X-Content-Type-Options': 'warning',
'Referrer-Policy': 'warning',
'Permissions-Policy': 'warning'
}

def normalize_url(target):
    if not target.startswith(('http://', 'https://')):
        return 'https://' + target
    return target

def check_target(target):
    target = normalize_url(target)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {'User-Agent': USER_AGENT}
    try:
        req = urllib.request.Request(target, headers=headers)
        return urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS, context=ctx)
    except Exception:
        return None

def validate_hsts(value):
    """
    Validates HSTS header.
    Requirement: max-age >= 120 days.
    Note: includeSubDomains is checked but not enforced as failure (per user request).
    """
    match = re.search(r'max-age=(\d+)', value.lower())
    if match:
        max_age = int(match.group(1))
        if max_age < HSTS_MIN_AGE:
            return True, f"max-age too low ({max_age})"
        return False, None
    return True, "invalid/missing max-age"

def validate_csp(value):
    """
    Validates CSP header.
    Rules:
    1. unsafe-eval is always misconfigured in script/default src (wasm-unsafe-eval is ignored).
    2. unsafe-inline is misconfigured in script/default src UNLESS nonce or hash is present.
    """
    csp_issues = []
    directives = value.split(';')
    parsed_directives = {}
    for directive in directives:
        directive = directive.strip()
        parts = directive.split()
        if not parts: continue
        d_name = parts[0].lower()
        parsed_directives[d_name] = parts[1:]
    
    # Determine effective script-src
    target_values = []
    if 'script-src' in parsed_directives:
        target_values = parsed_directives['script-src']
    elif 'default-src' in parsed_directives:
        target_values = parsed_directives['default-src']
    
    if target_values:
        # Check for unsafe-inline
        if "'unsafe-inline'" in target_values:
            has_nonce_or_hash = any(v.startswith(("'nonce-", "'sha")) for v in target_values)
            if not has_nonce_or_hash and "unsafe-inline" not in csp_issues:
                csp_issues.append("unsafe-inline")
        # Check for unsafe-eval (strictly bad, distinct from wasm-unsafe-eval)
        if "'unsafe-eval'" in target_values and "unsafe-eval" not in csp_issues:
            csp_issues.append("unsafe-eval")
            
    if csp_issues:
        return True, ", ".join(csp_issues)
    return False, None

def validate_header(header_name, value):
    """
    Dispatcher for header specific validation logic.
    Returns (is_misconfigured: bool, misconf_value: str | None)
    """
    header_lower = header_name.lower()
    if header_lower == 'x-xss-protection' and value == '0':
        return True, "0"
    elif header_lower == 'referrer-policy':
        if 'unsafe-url' in value.lower():
            return True, "unsafe-url"
    elif header_lower == 'strict-transport-security':
        return validate_hsts(value)
    elif header_lower == 'content-security-policy':
        return validate_csp(value)
    elif header_lower == 'x-frame-options':
        # Strict enforcement: Must be DENY or SAMEORIGIN
        if value.upper() not in ['DENY', 'SAMEORIGIN']:
            return True, f"bad value: {value}"
    elif header_lower == 'x-content-type-options':
        if 'nosniff' not in value.lower():
            return True, f"bad value: {value}"
    return False, None

def save_to_excel(results, filename):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
    except ImportError:
        print("Error: openpyxl not installed.")
        return
        
    wb = Workbook()
    ws = wb.active
    ws.title = "Security Headers Report"
    
    # Styles
    fill_ok = PatternFill(start_color="00FF00", end_color="00FF00", fill_type="solid")
    fill_missing = PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid")
    fill_misconfigured = PatternFill(start_color="FFFF00", end_color="FFFF00", fill_type="solid")
    header_font = Font(bold=True)
    center_aligned = Alignment(horizontal="center", vertical="center")
    thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))
    
    # write Header Row
    headers_list = list(SEC_HEADERS.keys())
    ws.append(["URL"] + headers_list)
    for cell in ws[1]:
        cell.font = header_font
        cell.alignment = center_aligned
        cell.border = thin_border
        
    row_idx = ws.max_row + 1
    for url, data in results.items():
        ws.cell(row=row_idx, column=1, value=url).border = thin_border
        present = data.get("present", {})
        missing = data.get("missing", [])
        
        for col_idx, header_name in enumerate(headers_list, start=2):
            cell_value = "N/A"
            cell_fill = None
            if header_name in missing:
                cell_value = "Missing"
                cell_fill = fill_missing
            elif header_name in present:
                value = present[header_name]
                is_bad, msg = validate_header(header_name, value)
                if is_bad:
                    cell_value = msg if msg else value
                    cell_fill = fill_misconfigured
                else:
                    cell_value = "OK"
                    cell_fill = fill_ok
            cell = ws.cell(row=row_idx, column=col_idx, value=cell_value)
            cell.alignment = center_aligned
            cell.border = thin_border
            if cell_fill:
                cell.fill = cell_fill
        row_idx += 1
        
    # Auto-adjust column widths
    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter
        for cell in column:
            try:
                val_len = len(str(cell.value))
                if val_len > max_length:
                    max_length = min(val_len, 50)
            except:
                pass
        ws.column_dimensions[column_letter].width = max_length + 2
        
    ws.freeze_panes = 'A2'
    ws.auto_filter.ref = ws.dimensions
    wb.save(filename)

def main():
    if len(sys.argv) != 3:
        print("Usage: python secure_headers.py <hosts_file> <output_xlsx>")
        sys.exit(1)
        
    hosts_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        with open(hosts_file, 'r') as f:
            targets = f.read().splitlines()
    except FileNotFoundError:
        print(f"Error: File {hosts_file} not found.")
        sys.exit(1)
        
    json_out = {}
    valid_targets = [t for t in targets if t.strip()]
    total_targets = len(valid_targets)
    
    # Progress bar setup
    pbar = None
    try:
        from tqdm import tqdm
        pbar = tqdm(total=total_targets, unit="site")
    except ImportError:
        print("Processing targets...")
        
    processed_count = 0
    for target in valid_targets:
        response = check_target(target)
        
        # Update progress
        if pbar:
            pbar.update(1)
            pbar.set_description(f"Scanning {target[:20]}")
        else:
            processed_count += 1
            print(f"[{processed_count}/{total_targets}] Scanning {target}...", end='\r')
            
        if not response:
            continue
            
        rUrl = response.geturl()
        headers = {k.lower(): v for k, v in response.getheaders()}
        
        json_results = {"present": {}, "missing": []}
        for header_name in SEC_HEADERS:
            header_lower = header_name.lower()
            if header_lower in headers:
                json_results["present"][header_name] = headers[header_lower]
            else:
                # HSTS only required on HTTPS
                if header_name == 'Strict-Transport-Security' and not rUrl.startswith('https://'):
                    continue
                json_results["missing"].append(header_name)
        
        json_out[rUrl] = json_results
        
    if pbar:
        pbar.close()
    else:
        print("\nScan complete.")
        
    save_to_excel(json_out, output_file)

if __name__ == "__main__":
    main()