"""
Database Auditor Module

This module provides system and database auditing functionality:
- SystemAuditor: Checks database file permissions and security settings
- LogAnalyzer: Scans audit logs for suspicious activity patterns
"""

import os
import stat
import re
import logging
from datetime import datetime, timedelta
from typing import Tuple, List, Dict, Any
from collections import defaultdict


class SystemAuditor:
    """
    Audits system-level security settings for the database.
    
    Checks:
    - Database file permissions
    - File ownership
    - Directory permissions
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def check_db_permissions(self, db_path: str) -> Tuple[bool, str]:
        """
        Verifies that the database file has secure, restrictive permissions.
        
        Secure permissions should be:
        - 600 (rw-------): Owner can read/write, no one else can access
        - 400 (r--------): Owner can read only (for read-only databases)
        
        Args:
            db_path: Path to the database file
            
        Returns:
            Tuple of (is_secure: bool, report: str)
            - is_secure: True if permissions are secure
            - report: Detailed report of permission status
        """
        if not os.path.exists(db_path):
            return False, f"ERROR: Database file not found at {db_path}"
        
        try:
            # Get file stats
            file_stats = os.stat(db_path)
            mode = file_stats.st_mode
            
            # Get permission bits (last 3 octal digits)
            perms = stat.S_IMODE(mode)
            perms_octal = oct(perms)[-3:]
            
            # Check if file is world-readable or world-writable
            world_readable = bool(mode & stat.S_IROTH)
            world_writable = bool(mode & stat.S_IWOTH)
            
            # Check if file is group-readable or group-writable
            group_readable = bool(mode & stat.S_IRGRP)
            group_writable = bool(mode & stat.S_IWGRP)
            
            # Build detailed report
            report_lines = [
                f"Database: {db_path}",
                f"Permissions: {perms_octal}",
                f"Owner: UID {file_stats.st_uid}",
                f"Group: GID {file_stats.st_gid}",
                ""
            ]
            
            # Check for security issues
            issues = []
            
            if world_readable:
                issues.append("⚠ WARNING: File is world-readable (any user can read)")
            
            if world_writable:
                issues.append("⚠ CRITICAL: File is world-writable (any user can modify)")
            
            if group_readable:
                issues.append("⚠ WARNING: File is group-readable (group members can read)")
            
            if group_writable:
                issues.append("⚠ CRITICAL: File is group-writable (group members can modify)")
            
            # Determine if permissions are secure
            # Secure permissions: 600 (rw-------) or 400 (r--------)
            is_secure = perms_octal in ['600', '400']
            
            if is_secure:
                report_lines.append("✓ SECURE: Database permissions are properly restricted")
                report_lines.append("  Only the owner can access the file")
            else:
                report_lines.append("✗ INSECURE: Database permissions are too permissive")
                report_lines.extend(issues)
                report_lines.append("")
                report_lines.append("RECOMMENDATION: Set permissions to 600 using:")
                report_lines.append(f"  chmod 600 {db_path}")
            
            report = "\n".join(report_lines)
            
            # Log the audit
            if is_secure:
                self.logger.info(f"Database permissions audit PASSED: {db_path} ({perms_octal})")
            else:
                self.logger.warning(f"Database permissions audit FAILED: {db_path} ({perms_octal})")
            
            return is_secure, report
            
        except Exception as e:
            error_msg = f"ERROR: Failed to check permissions: {str(e)}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def check_log_permissions(self, log_path: str) -> Tuple[bool, str]:
        """
        Verifies that the log file has secure permissions.
        
        Args:
            log_path: Path to the log file
            
        Returns:
            Tuple of (is_secure: bool, report: str)
        """
        # Similar logic to check_db_permissions
        return self.check_db_permissions(log_path)
    
    def audit_system_security(self, db_path: str, log_path: str) -> Dict[str, Any]:
        """
        Performs a comprehensive system security audit.
        
        Args:
            db_path: Path to the database file
            log_path: Path to the log file
            
        Returns:
            Dictionary with audit results
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "database": {},
            "log_file": {},
            "overall_secure": False
        }
        
        # Check database permissions
        db_secure, db_report = self.check_db_permissions(db_path)
        results["database"]["secure"] = db_secure
        results["database"]["report"] = db_report
        
        # Check log permissions
        log_secure, log_report = self.check_log_permissions(log_path)
        results["log_file"]["secure"] = log_secure
        results["log_file"]["report"] = log_report
        
        # Overall security status
        results["overall_secure"] = db_secure and log_secure
        
        return results


class LogAnalyzer:
    """
    Analyzes audit logs for suspicious activity patterns.
    
    Detects:
    - Rapid failed login attempts (brute force attacks)
    - Multiple failed attempts from different usernames
    - Account lockouts
    - Unusual access patterns
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Patterns to detect in logs
        self.failed_login_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*'
            r'(Failed login|FAIL: Credentials Mismatch|Access Denied).*'
            r'(user[:\s]+|username[:\s]+)?([a-zA-Z0-9_-]+)?',
            re.IGNORECASE
        )
        
        self.lockout_pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*'
            r'(LOCKOUT|locked out|lockout_until).*'
            r'(user[:\s]+|username[:\s]+)?([a-zA-Z0-9_-]+)?',
            re.IGNORECASE
        )
    
    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parses a timestamp string from the log file.
        
        Args:
            timestamp_str: Timestamp string in format 'YYYY-MM-DD HH:MM:SS'
            
        Returns:
            datetime object
        """
        try:
            return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            # Try alternative format
            try:
                return datetime.strptime(timestamp_str.split(',')[0], '%Y-%m-%d %H:%M:%S')
            except:
                return datetime.now()
    
    def scan_for_suspicious_activity(self, log_file: str) -> List[Dict[str, Any]]:
        """
        Scans the log file for suspicious activity patterns.
        
        Args:
            log_file: Path to the audit log file
            
        Returns:
            List of suspicious events, each as a dictionary with:
            - type: Type of suspicious activity
            - timestamp: When it occurred
            - description: Detailed description
            - severity: 'low', 'medium', 'high', 'critical'
            - details: Additional context
        """
        if not os.path.exists(log_file):
            self.logger.warning(f"Log file not found: {log_file}")
            return []
        
        suspicious_events = []
        failed_attempts = defaultdict(list)  # username -> list of timestamps
        
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            
            # Parse failed login attempts
            for line in lines:
                # Check for failed logins
                match = self.failed_login_pattern.search(line)
                if match:
                    timestamp_str = match.group(1)
                    username = match.group(4) if match.group(4) else "unknown"
                    timestamp = self.parse_timestamp(timestamp_str)
                    failed_attempts[username].append(timestamp)
                
                # Check for lockouts
                match = self.lockout_pattern.search(line)
                if match:
                    timestamp_str = match.group(1)
                    username = match.group(4) if match.group(4) else "unknown"
                    timestamp = self.parse_timestamp(timestamp_str)
                    
                    suspicious_events.append({
                        "type": "account_lockout",
                        "timestamp": timestamp.isoformat(),
                        "description": f"Account '{username}' was locked out due to too many failed attempts",
                        "severity": "high",
                        "details": {"username": username}
                    })
            
            # Analyze failed login patterns
            for username, timestamps in failed_attempts.items():
                if len(timestamps) >= 3:
                    # Sort timestamps
                    timestamps.sort()
                    
                    # Check for rapid attempts (5+ within 60 seconds)
                    for i in range(len(timestamps) - 4):
                        window_start = timestamps[i]
                        window_end = timestamps[i + 4]
                        time_diff = (window_end - window_start).total_seconds()
                        
                        if time_diff <= 60:
                            suspicious_events.append({
                                "type": "brute_force_attempt",
                                "timestamp": window_start.isoformat(),
                                "description": f"Rapid failed login attempts detected for '{username}' "
                                             f"(5 attempts in {time_diff:.0f} seconds)",
                                "severity": "critical",
                                "details": {
                                    "username": username,
                                    "attempt_count": 5,
                                    "time_window": time_diff,
                                    "first_attempt": window_start.isoformat(),
                                    "last_attempt": window_end.isoformat()
                                }
                            })
                            break  # Only report once per user
                    
                    # Check for persistent attempts (10+ over longer period)
                    if len(timestamps) >= 10:
                        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
                        suspicious_events.append({
                            "type": "persistent_attack",
                            "timestamp": timestamps[0].isoformat(),
                            "description": f"Persistent failed login attempts for '{username}' "
                                         f"({len(timestamps)} attempts over {time_span/60:.1f} minutes)",
                            "severity": "high",
                            "details": {
                                "username": username,
                                "total_attempts": len(timestamps),
                                "time_span_minutes": time_span / 60
                            }
                        })
            
            # Check for multiple username attempts (username enumeration)
            if len(failed_attempts) >= 5:
                # Get all timestamps across all users
                all_timestamps = []
                for timestamps in failed_attempts.values():
                    all_timestamps.extend(timestamps)
                all_timestamps.sort()
                
                if len(all_timestamps) >= 10:
                    time_span = (all_timestamps[-1] - all_timestamps[0]).total_seconds()
                    if time_span <= 300:  # Within 5 minutes
                        suspicious_events.append({
                            "type": "username_enumeration",
                            "timestamp": all_timestamps[0].isoformat(),
                            "description": f"Multiple usernames targeted in short time "
                                         f"({len(failed_attempts)} users, {len(all_timestamps)} attempts)",
                            "severity": "medium",
                            "details": {
                                "username_count": len(failed_attempts),
                                "total_attempts": len(all_timestamps),
                                "usernames": list(failed_attempts.keys())
                            }
                        })
            
            # Log the analysis results
            if suspicious_events:
                self.logger.warning(f"Log analysis found {len(suspicious_events)} suspicious events")
            else:
                self.logger.info("Log analysis found no suspicious activity")
            
            return suspicious_events
            
        except Exception as e:
            self.logger.error(f"Error scanning log file: {str(e)}")
            return []
    
    def generate_security_report(self, suspicious_events: List[Dict[str, Any]]) -> str:
        """
        Generates a formatted security report from suspicious events.
        
        Args:
            suspicious_events: List of suspicious events from scan_for_suspicious_activity
            
        Returns:
            Formatted report string
        """
        if not suspicious_events:
            return "✓ No suspicious activity detected in audit logs."
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_events = sorted(
            suspicious_events,
            key=lambda x: (severity_order.get(x["severity"], 4), x["timestamp"])
        )
        
        report_lines = [
            f"⚠ SECURITY ALERT: {len(suspicious_events)} suspicious event(s) detected",
            "=" * 70,
            ""
        ]
        
        for i, event in enumerate(sorted_events, 1):
            severity_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢"
            }.get(event["severity"], "⚪")
            
            report_lines.append(f"{i}. {severity_icon} {event['type'].upper().replace('_', ' ')}")
            report_lines.append(f"   Severity: {event['severity'].upper()}")
            report_lines.append(f"   Time: {event['timestamp']}")
            report_lines.append(f"   {event['description']}")
            report_lines.append("")
        
        return "\n".join(report_lines)
