#!/usr/bin/env python3
"""
Spiffy Private Chat - Host GUI
MIT Licensed - Free to use and modify

Beautiful PyQt6 interface for managing encrypted chat
"""

import sys
import secrets
from datetime import datetime, timedelta
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

try:
    import rust_private_chat
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: Rust crypto module not available")

class PrivateChatHostGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.links = {}  # token -> {url, created, expires, active}
        self.server_process = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("🔐 Spiffy Private Chat - Host Control")
        self.setGeometry(100, 100, 1200, 800)
        
        # Modern gradient background
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:1,
                    stop:0 #667eea, stop:1 #764ba2
                );
            }
            QWidget#centralWidget {
                background: transparent;
            }
            QPushButton {
                background: white;
                border: none;
                border-radius: 10px;
                padding: 15px 30px;
                font-size: 16px;
                font-weight: bold;
                color: #667eea;
            }
            QPushButton:hover {
                background: #f0f0f0;
                transform: scale(1.05);
            }
            QPushButton:pressed {
                background: #e0e0e0;
            }
            QLabel#header {
                color: white;
                font-size: 32px;
                font-weight: bold;
                padding: 20px;
            }
            QLabel#subtitle {
                color: rgba(255,255,255,0.9);
                font-size: 16px;
                padding: 10px;
            }
            QGroupBox {
                background: rgba(255,255,255,0.95);
                border-radius: 15px;
                padding: 20px;
                margin: 10px;
                font-size: 18px;
                font-weight: bold;
            }
            QListWidget {
                background: white;
                border: none;
                border-radius: 10px;
                padding: 10px;
                font-size: 14px;
            }
            QTextEdit {
                background: white;
                border: none;
                border-radius: 10px;
                padding: 10px;
                font-size: 14px;
            }
        """)
        
        # Central widget
        central = QWidget()
        central.setObjectName("centralWidget")
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header = QLabel("🔐 Spiffy Private Chat")
        header.setObjectName("header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        subtitle = QLabel("Encrypted Chat with Beautiful Interfaces • MIT Licensed")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("🚀 Start Server")
        self.start_btn.clicked.connect(self.start_server)
        btn_layout.addWidget(self.start_btn)
        
        self.gen_link_btn = QPushButton("🔗 Generate Link")
        self.gen_link_btn.clicked.connect(self.generate_link)
        self.gen_link_btn.setEnabled(False)
        btn_layout.addWidget(self.gen_link_btn)
        
        self.stop_btn = QPushButton("🛑 Stop Server")
        self.stop_btn.clicked.connect(self.stop_server)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)
        
        layout.addLayout(btn_layout)
        
        # Links section
        links_group = QGroupBox("📋 Active Links")
        links_layout = QVBoxLayout()
        
        self.links_list = QListWidget()
        self.links_list.setMinimumHeight(200)
        links_layout.addWidget(self.links_list)
        
        links_btn_layout = QHBoxLayout()
        copy_btn = QPushButton("📋 Copy Selected")
        copy_btn.clicked.connect(self.copy_selected_link)
        links_btn_layout.addWidget(copy_btn)
        
        revoke_btn = QPushButton("🚫 Revoke Selected")
        revoke_btn.clicked.connect(self.revoke_selected_link)
        links_btn_layout.addWidget(revoke_btn)
        
        links_layout.addLayout(links_btn_layout)
        links_group.setLayout(links_layout)
        layout.addWidget(links_group)
        
        # Chat activity
        activity_group = QGroupBox("💬 Live Chat Activity")
        activity_layout = QVBoxLayout()
        
        self.activity_view = QTextEdit()
        self.activity_view.setReadOnly(True)
        self.activity_view.setMinimumHeight(200)
        activity_layout.addWidget(self.activity_view)
        
        activity_group.setLayout(activity_layout)
        layout.addWidget(activity_group)
        
        # Status bar
        self.status_label = QLabel("⚪ Server stopped")
        self.status_label.setStyleSheet("color: white; font-size: 14px; padding: 10px;")
        layout.addWidget(self.status_label)
        
        central.setLayout(layout)
        self.setCentralWidget(central)
        
        # Check crypto availability
        if not CRYPTO_AVAILABLE:
            QMessageBox.warning(self, "Crypto Module Missing",
                              "Rust crypto module not found. Please build it first:\n"
                              "cd rust_private_chat && maturin develop --release")
    
    def start_server(self):
        """Start Flask server"""
        import subprocess
        try:
            self.server_process = subprocess.Popen(
                [sys.executable, "chat_web_server.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.gen_link_btn.setEnabled(True)
            self.status_label.setText("🟢 Server running on http://localhost:5001")
            self.activity_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] Server started")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start server: {e}")
    
    def stop_server(self):
        """Stop Flask server"""
        if self.server_process:
            self.server_process.terminate()
            self.server_process = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.gen_link_btn.setEnabled(False)
        self.status_label.setText("⚪ Server stopped")
        self.activity_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] Server stopped")
    
    def generate_link(self):
        """Generate unique access link"""
        token = secrets.token_urlsafe(32)
        url = f"http://localhost:5001/chat/{token}"
        
        created = datetime.now()
        expires = created + timedelta(hours=24)
        
        self.links[token] = {
            'url': url,
            'created': created,
            'expires': expires,
            'active': True
        }
        
        # Add to list
        item_text = f"🔗 {url}\n   Created: {created.strftime('%Y-%m-%d %H:%M')} | Expires: {expires.strftime('%Y-%m-%d %H:%M')}"
        self.links_list.addItem(item_text)
        
        # Show dialog
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Link Generated")
        dialog.setText("✅ New access link created!")
        dialog.setInformativeText(f"URL: {url}\n\nShare this link with users.")
        dialog.setStandardButtons(QMessageBox.StandardButton.Ok)
        
        # Copy to clipboard
        clipboard = QApplication.clipboard()
        clipboard.setText(url)
        dialog.setDetailedText("Link copied to clipboard!")
        
        dialog.exec()
        
        self.activity_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] Generated link: {token[:16]}...")
    
    def copy_selected_link(self):
        """Copy selected link to clipboard"""
        current = self.links_list.currentItem()
        if current:
            text = current.text()
            url = text.split('\n')[0].replace('🔗 ', '')
            clipboard = QApplication.clipboard()
            clipboard.setText(url)
            QMessageBox.information(self, "Copied", "Link copied to clipboard!")
    
    def revoke_selected_link(self):
        """Revoke selected link"""
        current_row = self.links_list.currentRow()
        if current_row >= 0:
            self.links_list.takeItem(current_row)
            QMessageBox.information(self, "Revoked", "Link has been revoked!")
            self.activity_view.append(f"[{datetime.now().strftime('%H:%M:%S')}] Link revoked")
    
    def closeEvent(self, event):
        """Clean up on close"""
        if self.server_process:
            self.server_process.terminate()
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Spiffy Private Chat")
    
    # Set app icon (if available)
    # app.setWindowIcon(QIcon('icon.png'))
    
    window = PrivateChatHostGUI()
    window.show()
    
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
