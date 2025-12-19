#!/usr/bin/env ruby
# Daily Security Scan Workflow
# Automated vulnerability assessment

require_relative '../omega_dsl'

Omega.workflow("Daily Vulnerability Scan") do
  puts "\n⚡ DAILY VULNERABILITY SCAN ⚡"
  puts "=" * 50
  
  # Scan local network
  scan "192.168.1.0/24", module: 'WIFI_RADAR', timeout: 60
  
  # Check for critical findings
  critical_findings = query(severity: 'CRITICAL', limit: 50)
  
  if critical_findings.any?
    alert("⚠️  Found #{critical_findings.length} CRITICAL findings!", severity: :critical)
    
    # Generate detailed report
    report format: :json, output: "critical_findings_#{Time.now.strftime('%Y%m%d')}.json"
  else
    puts "✅ No critical findings detected"
  end
  
  # Check for new devices
  recent_scans = query(module: 'WIFI_RADAR', limit: 100)
  unique_targets = recent_scans.map { |f| f[:target] }.uniq
  
  puts "\n📊 Scan Summary:"
  puts "   Devices found: #{unique_targets.length}"
  puts "   Total findings: #{recent_scans.length}"
  
  # Generate daily report
  report format: :text, output: "daily_report_#{Time.now.strftime('%Y%m%d')}.txt"
  
  puts "\n✅ Daily scan complete!"
end
