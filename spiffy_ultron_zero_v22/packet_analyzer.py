#!/usr/bin/env python3
"""
Real Packet Analyzer - Network Traffic Analysis
Uses Scapy for live packet capture and deep inspection
"""

import os
import sys
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional
import json

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, wrpcap
    from scapy.layers.http import HTTPRequest
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not installed. Run: pip install scapy")

class RealPacketSniffer:
    """Real-time packet capture and analysis using Scapy"""
    
    def __init__(self, interface: str = "en0"):
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for packet sniffing")
        
        self.interface = interface
        self.packets = []
        self.stats = defaultdict(int)
        self.threats = []
        self.connections = defaultdict(int)
        self.dns_queries = []
        self.http_requests = []
        
    def start_capture(self, duration: int = 60, packet_count: int = 1000, 
                     filter_expr: str = None) -> Dict[str, Any]:
        """
        Start live packet capture
        
        Args:
            duration: Capture duration in seconds
            packet_count: Maximum packets to capture
            filter_expr: BPF filter (e.g., "tcp port 80")
        
        Returns:
            Analysis results dictionary
        """
        print(f"🔍 Starting packet capture on {self.interface}...")
        print(f"   Duration: {duration}s | Max packets: {packet_count}")
        
        if filter_expr:
            print(f"   Filter: {filter_expr}")
        
        # Check for root privileges
        if os.geteuid() != 0:
            print("⚠️  WARNING: Packet sniffing requires root privileges")
            print("   Run with: sudo python3 packet_analyzer.py")
            return {"error": "Requires root privileges"}
        
        try:
            # Start sniffing
            self.packets = sniff(
                iface=self.interface,
                prn=self.analyze_packet,
                timeout=duration,
                count=packet_count,
                filter=filter_expr,
                store=True
            )
            
            print(f"\n✓ Captured {len(self.packets)} packets")
            
            # Analyze captured packets
            return self.generate_report()
            
        except PermissionError:
            return {"error": "Permission denied. Run with sudo."}
        except Exception as e:
            return {"error": f"Capture failed: {str(e)}"}
    
    def analyze_packet(self, packet):
        """Analyze individual packet in real-time"""
        try:
            # Update statistics
            self.stats['total'] += 1
            
            # Layer 3 - IP
            if IP in packet:
                self.stats['ip'] += 1
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Track connections
                conn_key = f"{src_ip}:{dst_ip}"
                self.connections[conn_key] += 1
                
                # Layer 4 - Transport
                if TCP in packet:
                    self.stats['tcp'] += 1
                    self._analyze_tcp(packet)
                    
                elif UDP in packet:
                    self.stats['udp'] += 1
                    self._analyze_udp(packet)
                    
                elif ICMP in packet:
                    self.stats['icmp'] += 1
                    self._analyze_icmp(packet)
            
            # Layer 2 - ARP
            elif ARP in packet:
                self.stats['arp'] += 1
                self._analyze_arp(packet)
                
        except Exception as e:
            self.stats['errors'] += 1
    
    def _analyze_tcp(self, packet):
        """Analyze TCP packets"""
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        
        # Track common ports
        if dst_port == 80 or src_port == 80:
            self.stats['http'] += 1
        elif dst_port == 443 or src_port == 443:
            self.stats['https'] += 1
        elif dst_port == 22 or src_port == 22:
            self.stats['ssh'] += 1
        
        # Detect SYN scan (port scanning)
        if flags == 'S':  # SYN flag only
            threat = {
                'type': 'Possible Port Scan',
                'source': packet[IP].src,
                'target': packet[IP].dst,
                'port': dst_port,
                'timestamp': datetime.now().isoformat()
            }
            if threat not in self.threats:
                self.threats.append(threat)
        
        # Check for HTTP traffic
        if Raw in packet:
            payload = packet[Raw].load
            if b'HTTP' in payload or b'GET' in payload or b'POST' in payload:
                try:
                    http_data = payload.decode('utf-8', errors='ignore')
                    if 'Host:' in http_data:
                        self.http_requests.append({
                            'src': packet[IP].src,
                            'dst': packet[IP].dst,
                            'data': http_data[:200]
                        })
                except:
                    pass
    
    def _analyze_udp(self, packet):
        """Analyze UDP packets"""
        dst_port = packet[UDP].dport
        
        # DNS traffic
        if dst_port == 53 or packet[UDP].sport == 53:
            self.stats['dns'] += 1
            if DNS in packet and packet[DNS].qd:
                query = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                self.dns_queries.append({
                    'query': query,
                    'src': packet[IP].src,
                    'timestamp': datetime.now().isoformat()
                })
    
    def _analyze_icmp(self, packet):
        """Analyze ICMP packets"""
        icmp_type = packet[ICMP].type
        
        # Detect ping sweeps
        if icmp_type == 8:  # Echo request
            self.stats['ping'] += 1
    
    def _analyze_arp(self, packet):
        """Analyze ARP packets for spoofing"""
        if packet[ARP].op == 2:  # ARP reply
            # Track ARP replies for duplicate IP detection
            arp_key = f"{packet[ARP].psrc}:{packet[ARP].hwsrc}"
            self.connections[arp_key] += 1
            
            # Simple ARP spoofing detection (multiple MACs for same IP)
            ip_mac_pairs = [k for k in self.connections.keys() if packet[ARP].psrc in k]
            if len(ip_mac_pairs) > 1:
                threat = {
                    'type': 'Possible ARP Spoofing',
                    'ip': packet[ARP].psrc,
                    'details': f"Multiple MACs detected for IP",
                    'timestamp': datetime.now().isoformat()
                }
                if threat not in self.threats:
                    self.threats.append(threat)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        
        # Calculate percentages
        total = self.stats['total']
        
        report = {
            'summary': {
                'total_packets': total,
                'duration': 'N/A',
                'interface': self.interface,
                'timestamp': datetime.now().isoformat()
            },
            'protocols': {
                'TCP': self.stats['tcp'],
                'UDP': self.stats['udp'],
                'ICMP': self.stats['icmp'],
                'ARP': self.stats['arp'],
                'IP': self.stats['ip']
            },
            'services': {
                'HTTP': self.stats['http'],
                'HTTPS': self.stats['https'],
                'DNS': self.stats['dns'],
                'SSH': self.stats['ssh']
            },
            'top_connections': dict(Counter(self.connections).most_common(10)),
            'dns_queries': self.dns_queries[:20],
            'http_requests': self.http_requests[:10],
            'threats': self.threats,
            'threat_count': len(self.threats)
        }
        
        return report
    
    def save_pcap(self, filename: str = "capture.pcap"):
        """Save captured packets to PCAP file"""
        if self.packets:
            wrpcap(filename, self.packets)
            print(f"✓ Saved {len(self.packets)} packets to {filename}")
            return filename
        return None
    
    def print_report(self, report: Dict[str, Any]):
        """Print formatted analysis report"""
        print("\n" + "="*70)
        print("📊 PACKET ANALYSIS REPORT")
        print("="*70)
        
        # Summary
        print(f"\n📈 Summary:")
        print(f"   Total Packets: {report['summary']['total_packets']}")
        print(f"   Interface: {report['summary']['interface']}")
        print(f"   Timestamp: {report['summary']['timestamp']}")
        
        # Protocols
        print(f"\n🔌 Protocols:")
        for proto, count in report['protocols'].items():
            if count > 0:
                print(f"   {proto}: {count}")
        
        # Services
        print(f"\n🌐 Services:")
        for service, count in report['services'].items():
            if count > 0:
                print(f"   {service}: {count}")
        
        # Top Connections
        if report['top_connections']:
            print(f"\n🔗 Top Connections:")
            for conn, count in list(report['top_connections'].items())[:5]:
                print(f"   {conn}: {count} packets")
        
        # DNS Queries
        if report['dns_queries']:
            print(f"\n🔍 Recent DNS Queries:")
            for query in report['dns_queries'][:5]:
                print(f"   {query['src']} → {query['query']}")
        
        # Threats
        if report['threats']:
            print(f"\n⚠️  THREATS DETECTED ({len(report['threats'])}):")
            for threat in report['threats']:
                print(f"   [{threat['type']}] {threat.get('source', 'N/A')} → {threat.get('target', threat.get('ip', 'N/A'))}")
        else:
            print(f"\n✓ No threats detected")
        
        print("\n" + "="*70)


def main():
    """CLI interface for packet analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-time Packet Analyzer')
    parser.add_argument('-i', '--interface', default='en0', help='Network interface')
    parser.add_argument('-t', '--time', type=int, default=30, help='Capture duration (seconds)')
    parser.add_argument('-c', '--count', type=int, default=1000, help='Max packet count')
    parser.add_argument('-f', '--filter', help='BPF filter expression')
    parser.add_argument('-o', '--output', help='Save PCAP file')
    parser.add_argument('--json', action='store_true', help='Output JSON report')
    
    args = parser.parse_args()
    
    if not SCAPY_AVAILABLE:
        print("❌ Scapy not installed. Install with: pip install scapy")
        sys.exit(1)
    
    # Create sniffer
    sniffer = RealPacketSniffer(interface=args.interface)
    
    # Start capture
    report = sniffer.start_capture(
        duration=args.time,
        packet_count=args.count,
        filter_expr=args.filter
    )
    
    if 'error' in report:
        print(f"❌ Error: {report['error']}")
        sys.exit(1)
    
    # Output results
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        sniffer.print_report(report)
    
    # Save PCAP if requested
    if args.output:
        sniffer.save_pcap(args.output)


if __name__ == "__main__":
    main()
