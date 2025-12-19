#!/usr/bin/env python3
"""
Omega Kernel - Advanced Logging System
Provides structured logging with rotation and multiple outputs
"""

import logging
import logging.handlers
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

class OmegaLogger:
    """Advanced logging system for Omega Kernel"""
    
    def __init__(self, log_dir: str = "omega_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Create loggers
        self.security_logger = self._create_logger("security", "security.log")
        self.performance_logger = self._create_logger("performance", "performance.log")
        self.error_logger = self._create_logger("error", "error.log")
        self.audit_logger = self._create_logger("audit", "audit.log")
    
    def _create_logger(self, name: str, filename: str) -> logging.Logger:
        """Create a logger (Console only - File logging disabled)"""
        logger = logging.getLogger(f"omega.{name}")
        logger.setLevel(logging.DEBUG)
        
        # File handler disabled
        # file_handler = logging.handlers.RotatingFileHandler(...)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def log_security_event(self, module: str, event: str, details: Dict[str, Any], severity: str = "INFO"):
        """Log security-related events"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module,
            "event": event,
            "details": details,
            "severity": severity
        }
        
        if severity == "CRITICAL":
            self.security_logger.critical(json.dumps(log_entry))
        elif severity == "ERROR":
            self.security_logger.error(json.dumps(log_entry))
        elif severity == "WARNING":
            self.security_logger.warning(json.dumps(log_entry))
        else:
            self.security_logger.info(json.dumps(log_entry))
    
    def log_performance(self, operation: str, duration_ms: float, details: Dict[str, Any] = None):
        """Log performance metrics"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "duration_ms": duration_ms,
            "details": details or {}
        }
        self.performance_logger.info(json.dumps(log_entry))
    
    def log_error(self, module: str, error: Exception, context: Dict[str, Any] = None):
        """Log errors with full context"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context or {}
        }
        self.error_logger.error(json.dumps(log_entry), exc_info=True)
    
    def log_audit(self, user: str, action: str, target: str, result: str):
        """Log audit trail for compliance"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "action": action,
            "target": target,
            "result": result
        }
        self.audit_logger.info(json.dumps(log_entry))

# Global logger instance
omega_logger = OmegaLogger()
