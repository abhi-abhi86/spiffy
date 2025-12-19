#!/usr/bin/env python3
"""
Omega Kernel - Data Analytics Module
Python-powered intelligence layer for network analysis
"""

import sqlite3
import json
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Any

class OmegaAnalytics:
    """Advanced analytics for security data"""
    
    def __init__(self, db_path: str = "ultron_zero.db"):
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
    
    def get_threat_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get threat summary for last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        query = """
            SELECT 
                severity,
                COUNT(*) as count,
                module
            FROM findings
            WHERE timestamp >= ?
            GROUP BY severity, module
        """
        
        cursor = self.db.execute(query, (cutoff.isoformat(),))
        results = cursor.fetchall()
        
        summary = {
            'total': 0,
            'by_severity': Counter(),
            'by_module': Counter(),
            'critical_modules': []
        }
        
        for row in results:
            summary['total'] += row['count']
            summary['by_severity'][row['severity']] += row['count']
            summary['by_module'][row['module']] += row['count']
            
            if row['severity'] == 'CRITICAL':
                summary['critical_modules'].append(row['module'])
        
        return summary
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """Detect unusual patterns in security data"""
        anomalies = []
        
        # Check for spike in findings
        recent = self._get_findings_count(hours=1)
        baseline = self._get_findings_count(hours=24) / 24
        
        if recent > baseline * 3:
            anomalies.append({
                'type': 'spike',
                'description': f'Findings spike detected: {recent} vs baseline {baseline:.1f}',
                'severity': 'WARNING'
            })
        
        # Check for new target patterns
        new_targets = self._detect_new_targets()
        if new_targets:
            anomalies.append({
                'type': 'new_targets',
                'description': f'New targets detected: {len(new_targets)}',
                'targets': new_targets,
                'severity': 'INFO'
            })
        
        return anomalies
    
    def generate_network_map(self) -> Dict[str, Any]:
        """Generate network topology map from scan data"""
        query = """
            SELECT DISTINCT target, module, details
            FROM findings
            WHERE module = 'WIFI_RADAR'
            ORDER BY timestamp DESC
            LIMIT 100
        """
        
        cursor = self.db.execute(query)
        results = cursor.fetchall()
        
        network_map = {
            'devices': [],
            'total': 0,
            'by_type': Counter()
        }
        
        for row in results:
            device = {
                'ip': row['target'],
                'details': row['details']
            }
            network_map['devices'].append(device)
            network_map['total'] += 1
            
            # Extract device type from details
            if 'iPhone' in row['details']:
                network_map['by_type']['iPhone'] += 1
            elif 'Samsung' in row['details']:
                network_map['by_type']['Samsung'] += 1
            elif 'Windows' in row['details']:
                network_map['by_type']['Windows'] += 1
            else:
                network_map['by_type']['Unknown'] += 1
        
        return network_map
    
    def get_module_performance(self) -> Dict[str, Any]:
        """Analyze module performance and usage"""
        query = """
            SELECT 
                module,
                COUNT(*) as executions,
                COUNT(CASE WHEN severity = 'ERROR' THEN 1 END) as errors,
                MIN(timestamp) as first_run,
                MAX(timestamp) as last_run
            FROM findings
            GROUP BY module
        """
        
        cursor = self.db.execute(query)
        results = cursor.fetchall()
        
        performance = {}
        for row in results:
            success_rate = ((row['executions'] - row['errors']) / row['executions'] * 100) if row['executions'] > 0 else 0
            
            performance[row['module']] = {
                'executions': row['executions'],
                'errors': row['errors'],
                'success_rate': round(success_rate, 2),
                'first_run': row['first_run'],
                'last_run': row['last_run']
            }
        
        return performance
    
    def export_analytics_report(self, output_file: str = "analytics_report.json"):
        """Generate comprehensive analytics report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'threat_summary': self.get_threat_summary(),
            'anomalies': self.detect_anomalies(),
            'network_map': self.generate_network_map(),
            'module_performance': self.get_module_performance()
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ Analytics report saved: {output_file}")
        return report
    
    # Helper methods
    
    def _get_findings_count(self, hours: int) -> int:
        """Get count of findings in last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        cursor = self.db.execute(
            "SELECT COUNT(*) FROM findings WHERE timestamp >= ?",
            (cutoff.isoformat(),)
        )
        return cursor.fetchone()[0]
    
    def _detect_new_targets(self, hours: int = 24) -> List[str]:
        """Detect targets that appeared recently"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        query = """
            SELECT DISTINCT target
            FROM findings
            WHERE timestamp >= ?
            AND target NOT IN (
                SELECT DISTINCT target
                FROM findings
                WHERE timestamp < ?
            )
        """
        
        cursor = self.db.execute(query, (cutoff.isoformat(), cutoff.isoformat()))
        return [row[0] for row in cursor.fetchall()]

if __name__ == "__main__":
    print("⚡ OMEGA KERNEL - ANALYTICS ENGINE ⚡")
    print("=" * 50)
    
    analytics = OmegaAnalytics()
    
    # Generate report
    report = analytics.export_analytics_report()
    
    print("\n📊 Analytics Summary:")
    print(f"   Total Findings: {report['threat_summary']['total']}")
    print(f"   Anomalies Detected: {len(report['anomalies'])}")
    print(f"   Network Devices: {report['network_map']['total']}")
    print(f"   Active Modules: {len(report['module_performance'])}")
