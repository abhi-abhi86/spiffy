#!/usr/bin/env python3
"""
Notification Manager - Multi-channel Alert System
Supports Email, Telegram, and Discord notifications
"""

import os
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional
from datetime import datetime
import configparser


class NotificationManager:
    """Multi-channel notification system"""
    
    def __init__(self, config_file: str = "notifications.conf"):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        
        # Load configuration
        if os.path.exists(config_file):
            self.config.read(config_file)
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration file"""
        self.config['email'] = {
            'enabled': 'false',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': '587',
            'from_email': 'your_email@gmail.com',
            'to_email': 'recipient@example.com',
            'password': 'your_app_password'
        }
        
        self.config['telegram'] = {
            'enabled': 'false',
            'bot_token': 'YOUR_BOT_TOKEN',
            'chat_id': 'YOUR_CHAT_ID'
        }
        
        self.config['discord'] = {
            'enabled': 'false',
            'webhook_url': 'YOUR_WEBHOOK_URL'
        }
        
        with open(self.config_file, 'w') as f:
            self.config.write(f)
        
        print(f"✓ Created default config: {self.config_file}")
        print(f"⚠️  Please edit {self.config_file} with your credentials")
    
    def send_notification(self, title: str, message: str, 
                         severity: str = "INFO", 
                         channels: List[str] = None):
        """
        Send notification to specified channels
        
        Args:
            title: Notification title
            message: Notification message
            severity: INFO, WARNING, ERROR, CRITICAL
            channels: List of channels (email, telegram, discord) or None for all enabled
        """
        # Format message with severity
        formatted_msg = f"[{severity}] {title}\n\n{message}"
        
        # Determine which channels to use
        if channels is None:
            channels = self._get_enabled_channels()
        
        results = {}
        
        # Send to each channel
        if 'email' in channels:
            results['email'] = self.send_email(title, formatted_msg)
        
        if 'telegram' in channels:
            results['telegram'] = self.send_telegram(formatted_msg)
        
        if 'discord' in channels:
            results['discord'] = self.send_discord(title, formatted_msg, severity)
        
        return results
    
    def _get_enabled_channels(self) -> List[str]:
        """Get list of enabled notification channels"""
        enabled = []
        
        for section in self.config.sections():
            if self.config.getboolean(section, 'enabled', fallback=False):
                enabled.append(section)
        
        return enabled
    
    def send_email(self, subject: str, body: str) -> bool:
        """Send email notification via SMTP"""
        try:
            if not self.config.getboolean('email', 'enabled', fallback=False):
                return False
            
            # Get email config
            smtp_server = self.config.get('email', 'smtp_server')
            smtp_port = self.config.getint('email', 'smtp_port')
            from_email = self.config.get('email', 'from_email')
            to_email = self.config.get('email', 'to_email')
            password = self.config.get('email', 'password')
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = f"[Spiffy Security] {subject}"
            msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
            
            # Add body
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(from_email, password)
                server.send_message(msg)
            
            print(f"✓ Email sent to {to_email}")
            return True
            
        except Exception as e:
            print(f"❌ Email failed: {e}")
            return False
    
    def send_telegram(self, message: str) -> bool:
        """Send Telegram notification via Bot API"""
        try:
            if not self.config.getboolean('telegram', 'enabled', fallback=False):
                return False
            
            bot_token = self.config.get('telegram', 'bot_token')
            chat_id = self.config.get('telegram', 'chat_id')
            
            # Telegram API endpoint
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            
            # Format message with markdown
            formatted_message = f"🔒 *Spiffy Security Alert*\n\n{message}"
            
            # Send request
            payload = {
                'chat_id': chat_id,
                'text': formatted_message,
                'parse_mode': 'Markdown'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            
            print(f"✓ Telegram message sent")
            return True
            
        except Exception as e:
            print(f"❌ Telegram failed: {e}")
            return False
    
    def send_discord(self, title: str, message: str, severity: str = "INFO") -> bool:
        """Send Discord notification via Webhook"""
        try:
            if not self.config.getboolean('discord', 'enabled', fallback=False):
                return False
            
            webhook_url = self.config.get('discord', 'webhook_url')
            
            # Color based on severity
            color_map = {
                'INFO': 0x3498db,      # Blue
                'WARNING': 0xf39c12,   # Orange
                'ERROR': 0xe74c3c,     # Red
                'CRITICAL': 0x992d22   # Dark Red
            }
            color = color_map.get(severity, 0x95a5a6)
            
            # Create embed
            embed = {
                'title': f'🔒 {title}',
                'description': message,
                'color': color,
                'timestamp': datetime.utcnow().isoformat(),
                'footer': {
                    'text': 'Spiffy Security Suite'
                }
            }
            
            payload = {
                'embeds': [embed]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            print(f"✓ Discord webhook sent")
            return True
            
        except Exception as e:
            print(f"❌ Discord failed: {e}")
            return False
    
    def test_notifications(self):
        """Test all enabled notification channels"""
        print("\n" + "="*70)
        print("🧪 TESTING NOTIFICATION CHANNELS")
        print("="*70)
        
        test_title = "Test Notification"
        test_message = f"This is a test notification sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        results = self.send_notification(
            title=test_title,
            message=test_message,
            severity="INFO"
        )
        
        print("\nResults:")
        for channel, success in results.items():
            status = "✓ SUCCESS" if success else "❌ FAILED"
            print(f"  {channel}: {status}")
        
        print("="*70)
        
        return results
    
    def get_config_status(self) -> dict:
        """Get configuration status for all channels"""
        status = {}
        
        for section in ['email', 'telegram', 'discord']:
            if section in self.config:
                status[section] = {
                    'enabled': self.config.getboolean(section, 'enabled', fallback=False),
                    'configured': self._is_channel_configured(section)
                }
        
        return status
    
    def _is_channel_configured(self, channel: str) -> bool:
        """Check if channel has valid configuration"""
        if channel == 'email':
            return (
                self.config.get('email', 'from_email', fallback='') != 'your_email@gmail.com' and
                self.config.get('email', 'password', fallback='') != 'your_app_password'
            )
        elif channel == 'telegram':
            return (
                self.config.get('telegram', 'bot_token', fallback='') != 'YOUR_BOT_TOKEN' and
                self.config.get('telegram', 'chat_id', fallback='') != 'YOUR_CHAT_ID'
            )
        elif channel == 'discord':
            return (
                self.config.get('discord', 'webhook_url', fallback='') != 'YOUR_WEBHOOK_URL'
            )
        
        return False
    
    def print_status(self):
        """Print configuration status"""
        status = self.get_config_status()
        
        print("\n" + "="*70)
        print("📢 NOTIFICATION CONFIGURATION STATUS")
        print("="*70)
        
        for channel, info in status.items():
            enabled_str = "✓ ENABLED" if info['enabled'] else "✗ DISABLED"
            config_str = "✓ Configured" if info['configured'] else "⚠️  Not Configured"
            
            print(f"\n{channel.upper()}:")
            print(f"  Status: {enabled_str}")
            print(f"  Config: {config_str}")
        
        print("\n" + "="*70)
        print(f"Config file: {self.config_file}")
        print("="*70)


def main():
    """CLI interface for notification manager"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Notification Manager')
    parser.add_argument('--test', action='store_true', help='Test all notifications')
    parser.add_argument('--test-email', action='store_true', help='Test email only')
    parser.add_argument('--test-telegram', action='store_true', help='Test Telegram only')
    parser.add_argument('--test-discord', action='store_true', help='Test Discord only')
    parser.add_argument('--status', action='store_true', help='Show configuration status')
    parser.add_argument('--send', nargs=2, metavar=('TITLE', 'MESSAGE'), help='Send custom notification')
    parser.add_argument('--channels', nargs='+', choices=['email', 'telegram', 'discord'], 
                       help='Specify channels')
    
    args = parser.parse_args()
    
    notifier = NotificationManager()
    
    if args.status:
        notifier.print_status()
    
    elif args.test:
        notifier.test_notifications()
    
    elif args.test_email:
        result = notifier.send_email("Test Email", "This is a test email from Spiffy Security")
        print(f"Email test: {'✓ SUCCESS' if result else '❌ FAILED'}")
    
    elif args.test_telegram:
        result = notifier.send_telegram("Test Telegram message from Spiffy Security")
        print(f"Telegram test: {'✓ SUCCESS' if result else '❌ FAILED'}")
    
    elif args.test_discord:
        result = notifier.send_discord("Test Discord", "This is a test from Spiffy Security", "INFO")
        print(f"Discord test: {'✓ SUCCESS' if result else '❌ FAILED'}")
    
    elif args.send:
        title, message = args.send
        results = notifier.send_notification(
            title=title,
            message=message,
            channels=args.channels
        )
        print(f"Sent to: {', '.join(results.keys())}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
