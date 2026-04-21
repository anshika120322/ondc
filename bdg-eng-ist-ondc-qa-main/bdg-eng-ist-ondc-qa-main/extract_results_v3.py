import re, os, glob

def extract_summary(filepath):
    size = os.path.getsize(filepath)
    read_size = min(size, 300000)
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
        content = fh.read(read_size)
    
    result = {}
    
    # Format A (dark theme): scard
    m_total = re.search(r'<div class="scard total"[^>]*>\s*<div class="val"[^>]*>(\d+)', content, re.S)
    m_passed = re.search(r'<div class="scard passed"[^>]*>\s*<div class="val"[^>]*>(\d+)', content, re.S)
    m_failed = re.search(r'<div class="scard failed"[^>]*>\s*<div class="val"[^>]*>(\d+)', content, re.S)
    m_rate = re.search(r'<div class="scard rate"[^>]*>\s*<div class="val"[^>]*>([\d.]+)%', content, re.S)
    
    if m_total:
        result['total'] = int(m_total.group(1))
        result['passed'] = int(m_passed.group(1)) if m_passed else 0
        result['failed'] = int(m_failed.group(1)) if m_failed else 0
        result['rate'] = m_rate.group(1) if m_rate else ''
        return result
    
    # Format B (light theme): summary-card with label-first layout
    pairs = re.findall(
        r'<div class="summary-card([^"]*)"[^>]*>\s*<div class="label">([^<]+)</div>\s*<div class="value">([^<]+)</div>',
        content, re.S
    )
    if pairs:
        for cls, label, value in pairs:
            label_lower = label.strip().lower()
            if label_lower == 'passed':
                result['passed'] = int(value.strip())
            elif label_lower == 'failed':
                result['failed'] = int(value.strip())
            elif label_lower == 'total':
                result['total'] = int(value.strip())
            elif 'pass rate' in label_lower:
                result['rate'] = value.strip().replace('%', '')
        if 'passed' in result:
            if 'total' not in result:
                result['total'] = result.get('passed', 0) + result.get('failed', 0)
            if 'rate' not in result and result['total'] > 0:
                result['rate'] = f"{100 * result['passed'] / result['total']:.1f}"
            return result
    
    # Fallback: count test-header classes
    pass_count = len(re.findall(r'class="test-header\s+passed"', content))
    fail_count = len(re.findall(r'class="test-header\s+failed"', content))
    if pass_count > 0 or fail_count > 0:
        result['passed'] = pass_count
        result['failed'] = fail_count
        result['total'] = pass_count + fail_count
        result['rate'] = f'{100*pass_count/(pass_count+fail_count):.1f}' if (pass_count+fail_count) > 0 else '0'
        result['note'] = '(from class count)'
    return result

folders = {
    'zip1': ('C:/Users/RamkumarJeyaram/Downloads/zip1', 'Gateway-Workflow'),
    'zip2': ('C:/Users/RamkumarJeyaram/Downloads/zip2', 'Gateway-API'),
    'zip3': ('C:/Users/RamkumarJeyaram/Downloads/zip3', 'Admin-WF'),
    'zip4': ('C:/Users/RamkumarJeyaram/Downloads/zip4', 'Registry'),
}

all_results = {}
for key, (folder, label) in folders.items():
    files = sorted(glob.glob(os.path.join(folder, '*.html')))
    print(f'\n===== {label} ({key}) =====')
    folder_total = 0
    folder_passed = 0
    folder_failed = 0
    for f in files:
        fname = os.path.basename(f)
        r = extract_summary(f)
        t = r.get('total', 0)
        p = r.get('passed', 0)
        fl = r.get('failed', 0)
        rate = r.get('rate', 'N/A')
        note = r.get('note', '')
        folder_total += t
        folder_passed += p
        folder_failed += fl
        print(f'  {fname}: Total={t} Pass={p} Fail={fl} Rate={rate}% {note}')
    
    pct = f'{100*folder_passed/folder_total:.1f}' if folder_total > 0 else 'N/A'
    print(f'  --- SUBTOTAL: Total={folder_total} Pass={folder_passed} Fail={folder_failed} Rate={pct}%')
    all_results[key] = {'total': folder_total, 'passed': folder_passed, 'failed': folder_failed, 'rate': pct}

# === COMPONENT MAPPING ===
# Gateway = zip1 (workflow) + zip2 (API)
gw_total = all_results['zip1']['total'] + all_results['zip2']['total']
gw_passed = all_results['zip1']['passed'] + all_results['zip2']['passed']
gw_failed = all_results['zip1']['failed'] + all_results['zip2']['failed']
gw_rate = f'{100*gw_passed/gw_total:.1f}' if gw_total > 0 else 'N/A'

# Admin = zip3
adm = all_results['zip3']

# Registry = zip4
reg = all_results['zip4']

print('\n\n========== FINAL TABLE ==========')
print(f'{"Component":<25} {"Happy-path":<15} {"Negative":<15} {"Total":<10} {"Pass %":<12}')
print('-' * 77)
print(f'{"Registry":<25} {"109":<15} {"132":<15} {"241":<10} {reg["rate"]+"%":<12}')
print(f'{"Admin":<25} {"25":<15} {"28":<15} {"53":<10} {adm["rate"]+"%":<12}')
print(f'{"Admin Portal (Manual)":<25} {"13":<15} {"20":<15} {"33":<10} {"N/A":<12}')
print(f'{"Gateway":<25} {"340":<15} {"274":<15} {"614":<10} {gw_rate+"%":<12}')

# Overall = exclude manual (33 tests)
auto_total = gw_total + int(adm['total']) + int(reg['total'])
auto_passed = gw_passed + int(adm['passed']) + int(reg['passed'])
auto_failed = gw_failed + int(adm['failed']) + int(reg['failed'])
overall_rate = f'{100*auto_passed/auto_total:.1f}' if auto_total > 0 else 'N/A'
print(f'{"Overall total":<25} {"487":<15} {"454":<15} {"941":<10} {overall_rate+"%":<12}')
print(f'\n  (Automated: {auto_total} tests, {auto_passed} pass, {auto_failed} fail)')
