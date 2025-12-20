#!/usr/bin/env python3
"""
Scan Scheduler - Automated Security Scan Scheduling
Uses APScheduler for cron-like job scheduling
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
import asyncio

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    SCHEDULER_AVAILABLE = True
except ImportError:
    SCHEDULER_AVAILABLE = False
    print("⚠️  APScheduler not installed. Run: pip install APScheduler")


class ScanScheduler:
    """Automated scan scheduling and management"""
    
    def __init__(self, config_file: str = "scan_schedule.json"):
        if not SCHEDULER_AVAILABLE:
            raise ImportError("APScheduler is required")
        
        self.config_file = config_file
        self.scheduler = BackgroundScheduler()
        self.jobs = {}
        self.execution_history = []
        self.notifier = None
        
        # Load existing jobs
        self.load_jobs()
    
    def set_notifier(self, notifier):
        """Set notification manager for alerts"""
        self.notifier = notifier
    
    def add_job(self, name: str, module: str, schedule: str, 
                enabled: bool = True, notify_channels: List[str] = None,
                **kwargs) -> bool:
        """
        Add a scheduled scan job
        
        Args:
            name: Job name/identifier
            module: Module to run (WIFI_RADAR, VULN_SCANNER, etc.)
            schedule: Cron expression (e.g., "0 2 * * *") or interval (e.g., "1h", "30m")
            enabled: Whether job is active
            notify_channels: List of notification channels
            **kwargs: Additional module-specific parameters
        
        Returns:
            True if job added successfully
        """
        try:
            # Parse schedule
            trigger = self._parse_schedule(schedule)
            
            # Create job config
            job_config = {
                'name': name,
                'module': module,
                'schedule': schedule,
                'enabled': enabled,
                'notify_channels': notify_channels or [],
                'params': kwargs,
                'created': datetime.now().isoformat(),
                'last_run': None,
                'run_count': 0
            }
            
            # Add to scheduler if enabled
            if enabled:
                job = self.scheduler.add_job(
                    func=self._execute_scan,
                    trigger=trigger,
                    args=[name, module, kwargs],
                    id=name,
                    name=name,
                    replace_existing=True
                )
                job_config['scheduler_id'] = job.id
            
            # Store job
            self.jobs[name] = job_config
            self.save_jobs()
            
            print(f"✓ Added job '{name}' - {module} ({schedule})")
            return True
            
        except Exception as e:
            print(f"❌ Failed to add job: {e}")
            return False
    
    def _parse_schedule(self, schedule: str):
        """Parse schedule string into APScheduler trigger"""
        # Check if it's an interval (e.g., "1h", "30m", "2d")
        if schedule[-1] in ['h', 'm', 'd', 's']:
            unit_map = {'h': 'hours', 'm': 'minutes', 'd': 'days', 's': 'seconds'}
            value = int(schedule[:-1])
            unit = unit_map[schedule[-1]]
            return IntervalTrigger(**{unit: value})
        
        # Otherwise treat as cron expression
        parts = schedule.split()
        if len(parts) == 5:
            # Standard cron: minute hour day month day_of_week
            return CronTrigger(
                minute=parts[0],
                hour=parts[1],
                day=parts[2],
                month=parts[3],
                day_of_week=parts[4]
            )
        else:
            raise ValueError(f"Invalid schedule format: {schedule}")
    
    def _execute_scan(self, job_name: str, module: str, params: Dict):
        """Execute a scheduled scan"""
        print(f"\n🔄 Executing scheduled job: {job_name}")
        print(f"   Module: {module}")
        print(f"   Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            # Update job stats
            if job_name in self.jobs:
                self.jobs[job_name]['last_run'] = datetime.now().isoformat()
                self.jobs[job_name]['run_count'] += 1
                self.save_jobs()
            
            # Execute the scan (this will be integrated with spiffy.py modules)
            result = self._run_module(module, params)
            
            # Log execution
            execution_record = {
                'job_name': job_name,
                'module': module,
                'timestamp': datetime.now().isoformat(),
                'status': 'success' if result else 'failed',
                'result': result
            }
            self.execution_history.append(execution_record)
            
            # Send notification
            if self.notifier and self.jobs[job_name].get('notify_channels'):
                self._send_notification(job_name, module, result)
            
            print(f"✓ Job '{job_name}' completed successfully")
            
        except Exception as e:
            print(f"❌ Job '{job_name}' failed: {e}")
            
            # Log failure
            execution_record = {
                'job_name': job_name,
                'module': module,
                'timestamp': datetime.now().isoformat(),
                'status': 'error',
                'error': str(e)
            }
            self.execution_history.append(execution_record)
    
    def _run_module(self, module: str, params: Dict) -> Dict:
        """
        Run a security module
        This is a placeholder - will be integrated with actual spiffy.py modules
        """
        # Import and run the appropriate module
        # For now, return a mock result
        return {
            'module': module,
            'status': 'completed',
            'findings': [],
            'timestamp': datetime.now().isoformat()
        }
    
    def _send_notification(self, job_name: str, module: str, result: Dict):
        """Send notification about scan completion"""
        if not self.notifier:
            return
        
        channels = self.jobs[job_name].get('notify_channels', [])
        
        title = f"Scheduled Scan Complete: {job_name}"
        message = f"""
Module: {module}
Status: {result.get('status', 'unknown')}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Findings: {len(result.get('findings', []))}
"""
        
        self.notifier.send_notification(
            title=title,
            message=message,
            severity="INFO",
            channels=channels
        )
    
    def remove_job(self, name: str) -> bool:
        """Remove a scheduled job"""
        try:
            if name in self.jobs:
                # Remove from scheduler
                if self.scheduler.get_job(name):
                    self.scheduler.remove_job(name)
                
                # Remove from jobs dict
                del self.jobs[name]
                self.save_jobs()
                
                print(f"✓ Removed job '{name}'")
                return True
            else:
                print(f"❌ Job '{name}' not found")
                return False
        except Exception as e:
            print(f"❌ Failed to remove job: {e}")
            return False
    
    def pause_job(self, name: str) -> bool:
        """Pause a scheduled job"""
        try:
            if self.scheduler.get_job(name):
                self.scheduler.pause_job(name)
                self.jobs[name]['enabled'] = False
                self.save_jobs()
                print(f"⏸  Paused job '{name}'")
                return True
            return False
        except Exception as e:
            print(f"❌ Failed to pause job: {e}")
            return False
    
    def resume_job(self, name: str) -> bool:
        """Resume a paused job"""
        try:
            if self.scheduler.get_job(name):
                self.scheduler.resume_job(name)
                self.jobs[name]['enabled'] = True
                self.save_jobs()
                print(f"▶️  Resumed job '{name}'")
                return True
            return False
        except Exception as e:
            print(f"❌ Failed to resume job: {e}")
            return False
    
    def list_jobs(self) -> List[Dict]:
        """List all scheduled jobs"""
        return list(self.jobs.values())
    
    def get_job(self, name: str) -> Optional[Dict]:
        """Get job details"""
        return self.jobs.get(name)
    
    def get_execution_history(self, job_name: str = None, limit: int = 50) -> List[Dict]:
        """Get execution history"""
        if job_name:
            history = [h for h in self.execution_history if h['job_name'] == job_name]
        else:
            history = self.execution_history
        
        return history[-limit:]
    
    def start(self):
        """Start the scheduler"""
        if not self.scheduler.running:
            self.scheduler.start()
            print("✓ Scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            print("✓ Scheduler stopped")
    
    def save_jobs(self):
        """Save jobs to config file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump({
                    'jobs': self.jobs,
                    'history': self.execution_history[-100:]  # Keep last 100
                }, f, indent=2)
        except Exception as e:
            print(f"⚠️  Failed to save jobs: {e}")
    
    def load_jobs(self):
        """Load jobs from config file"""
        if not os.path.exists(self.config_file):
            return
        
        try:
            with open(self.config_file, 'r') as f:
                data = json.load(f)
                self.jobs = data.get('jobs', {})
                self.execution_history = data.get('history', [])
            
            # Re-add enabled jobs to scheduler
            for name, job in self.jobs.items():
                if job.get('enabled', True):
                    try:
                        trigger = self._parse_schedule(job['schedule'])
                        self.scheduler.add_job(
                            func=self._execute_scan,
                            trigger=trigger,
                            args=[name, job['module'], job.get('params', {})],
                            id=name,
                            name=name,
                            replace_existing=True
                        )
                    except Exception as e:
                        print(f"⚠️  Failed to load job '{name}': {e}")
            
            print(f"✓ Loaded {len(self.jobs)} jobs from {self.config_file}")
            
        except Exception as e:
            print(f"⚠️  Failed to load jobs: {e}")
    
    def print_jobs(self):
        """Print formatted job list"""
        if not self.jobs:
            print("No scheduled jobs")
            return
        
        print("\n" + "="*70)
        print("📅 SCHEDULED JOBS")
        print("="*70)
        
        for name, job in self.jobs.items():
            status = "✓ ENABLED" if job.get('enabled') else "⏸ PAUSED"
            print(f"\n[{status}] {name}")
            print(f"   Module: {job['module']}")
            print(f"   Schedule: {job['schedule']}")
            print(f"   Last Run: {job.get('last_run', 'Never')}")
            print(f"   Run Count: {job.get('run_count', 0)}")
            if job.get('notify_channels'):
                print(f"   Notifications: {', '.join(job['notify_channels'])}")
        
        print("\n" + "="*70)


def main():
    """CLI interface for scheduler"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Scan Scheduler')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Add job
    add_parser = subparsers.add_parser('add', help='Add a scheduled job')
    add_parser.add_argument('name', help='Job name')
    add_parser.add_argument('module', help='Module to run')
    add_parser.add_argument('schedule', help='Cron expression or interval (e.g., "0 2 * * *" or "1h")')
    add_parser.add_argument('--notify', nargs='+', help='Notification channels')
    
    # Remove job
    remove_parser = subparsers.add_parser('remove', help='Remove a job')
    remove_parser.add_argument('name', help='Job name')
    
    # List jobs
    subparsers.add_parser('list', help='List all jobs')
    
    # Pause/Resume
    pause_parser = subparsers.add_parser('pause', help='Pause a job')
    pause_parser.add_argument('name', help='Job name')
    
    resume_parser = subparsers.add_parser('resume', help='Resume a job')
    resume_parser.add_argument('name', help='Job name')
    
    # History
    history_parser = subparsers.add_parser('history', help='Show execution history')
    history_parser.add_argument('--job', help='Filter by job name')
    history_parser.add_argument('--limit', type=int, default=20, help='Number of records')
    
    # Start daemon
    subparsers.add_parser('start', help='Start scheduler daemon')
    
    args = parser.parse_args()
    
    if not SCHEDULER_AVAILABLE:
        print("❌ APScheduler not installed. Install with: pip install APScheduler")
        return
    
    scheduler = ScanScheduler()
    
    if args.command == 'add':
        scheduler.add_job(
            name=args.name,
            module=args.module,
            schedule=args.schedule,
            notify_channels=args.notify
        )
    
    elif args.command == 'remove':
        scheduler.remove_job(args.name)
    
    elif args.command == 'list':
        scheduler.print_jobs()
    
    elif args.command == 'pause':
        scheduler.pause_job(args.name)
    
    elif args.command == 'resume':
        scheduler.resume_job(args.name)
    
    elif args.command == 'history':
        history = scheduler.get_execution_history(args.job, args.limit)
        print(json.dumps(history, indent=2))
    
    elif args.command == 'start':
        print("Starting scheduler daemon...")
        scheduler.start()
        print("Press Ctrl+C to stop")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            scheduler.stop()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
