#!/usr/bin/env python3
"""
Database Viewer for SPIFFY Ultron Zero
View all stored scan results and findings
"""

import sqlite3
import json
from datetime import datetime

DB_FILE = "ultron_zero.db"

def view_all_findings():
    """Display all findings from the database"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all findings
    cursor.execute("""
        SELECT f.*, i.username 
        FROM findings f
        LEFT JOIN identities i ON f.user_id = i.id
        ORDER BY f.timestamp DESC
    """)
    
    findings = cursor.fetchall()
    
    if not findings:
        print("📭 No scan data stored yet.")
        print("\nRun some scans first:")
        print("  - WIFI_RADAR to scan your network")
        print("  - DNS_ENUM to discover subdomains")
        print("  - VULN_SCANNER to find vulnerabilities")
        print("  - PASSWORD_CRACKER to test hashes")
        return
    
    print(f"\n{'='*100}")
    print(f"📊 SPIFFY SCAN DATABASE - {len(findings)} FINDINGS")
    print(f"{'='*100}\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"[{i}] {finding['timestamp']}")
        print(f"    Module: {finding['module']}")
        print(f"    Target: {finding['target']}")
        print(f"    Severity: {finding['severity']}")
        print(f"    User: {finding['username'] or 'Unknown'}")
        
        # Parse and display details
        try:
            details = json.loads(finding['details'])
            if isinstance(details, dict):
                for key, value in details.items():
                    if isinstance(value, list) and len(value) > 5:
                        print(f"    {key}: {len(value)} items")
                    else:
                        print(f"    {key}: {value}")
            else:
                print(f"    Details: {details}")
        except:
            print(f"    Details: {finding['details']}")
        
        print()
    
    conn.close()

def view_by_module():
    """View findings grouped by module"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT module, COUNT(*) as count, MAX(timestamp) as last_scan
        FROM findings
        GROUP BY module
        ORDER BY count DESC
    """)
    
    modules = cursor.fetchall()
    
    if not modules:
        print("📭 No scan data stored yet.")
        return
    
    print(f"\n{'='*80}")
    print(f"📈 SCAN STATISTICS BY MODULE")
    print(f"{'='*80}\n")
    
    for mod in modules:
        print(f"  {mod['module'].ljust(20)} - {mod['count']} scans (Last: {mod['last_scan']})")
    
    print()
    conn.close()

def export_findings():
    """Export all findings to JSON file"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM findings ORDER BY timestamp DESC")
    findings = cursor.fetchall()
    
    export_data = []
    for finding in findings:
        export_data.append({
            "id": finding['id'],
            "module": finding['module'],
            "target": finding['target'],
            "details": json.loads(finding['details']) if finding['details'] else None,
            "severity": finding['severity'],
            "timestamp": finding['timestamp']
        })
    
    filename = f"spiffy_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(export_data, f, indent=2)
    
    print(f"✅ Exported {len(findings)} findings to {filename}")
    conn.close()

if __name__ == "__main__":
    print("\n🔍 SPIFFY DATABASE VIEWER\n")
    print("[1] View All Findings")
    print("[2] View Statistics by Module")
    print("[3] Export to JSON")
    print("[0] Exit")
    
    choice = input("\nSelect option: ").strip()
    
    if choice == '1':
        view_all_findings()
    elif choice == '2':
        view_by_module()
    elif choice == '3':
        export_findings()
    else:
        print("Goodbye!")
