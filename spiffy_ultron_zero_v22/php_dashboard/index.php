<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚡ Omega Kernel Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #00ff88;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container { max-width: 1400px; margin: 0 auto; }
        
        .header {
            text-align: center;
            padding: 30px;
            background: rgba(0, 255, 136, 0.1);
            border: 2px solid #00ff88;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }
        
        .header h1 {
            font-size: 2.5em;
            text-shadow: 0 0 10px #00ff88;
            margin-bottom: 10px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(0, 255, 136, 0.05);
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0, 255, 136, 0.3);
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #00ff88;
            text-shadow: 0 0 10px #00ff88;
        }
        
        .stat-card .label {
            color: #00ccff;
            margin-top: 10px;
            font-size: 0.9em;
        }
        
        .filters {
            background: rgba(0, 255, 136, 0.05);
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filters select, .filters input {
            background: #0a0e27;
            border: 1px solid #00ff88;
            color: #00ff88;
            padding: 8px 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }
        
        .filters button {
            background: #00ff88;
            color: #0a0e27;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        
        .filters button:hover {
            background: #00ccff;
            transform: scale(1.05);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(0, 255, 136, 0.05);
            border: 1px solid #00ff88;
            border-radius: 8px;
            overflow: hidden;
        }
        
        th {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
            padding: 15px;
            text-align: left;
            font-weight: bold;
            border-bottom: 2px solid #00ff88;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
        }
        
        tr:hover { background: rgba(0, 255, 136, 0.1); }
        
        .severity-CRITICAL { color: #ff4444; font-weight: bold; }
        .severity-ERROR { color: #ff8844; }
        .severity-WARNING { color: #ffcc00; }
        .severity-INFO { color: #00ccff; }
        
        .module-badge {
            background: rgba(0, 255, 136, 0.2);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            display: inline-block;
        }
        
        .auto-refresh {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(0, 255, 136, 0.9);
            color: #0a0e27;
            padding: 10px 20px;
            border-radius: 20px;
            font-weight: bold;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ OMEGA KERNEL DASHBOARD ⚡</h1>
            <p>STARK INDUSTRIES - CLASSIFIED SECURITY PLATFORM</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Real-Time Audit Log Monitoring</p>
        </div>
        
        <div id="stats" class="stats"></div>
        
        <div class="filters">
            <label>Module:</label>
            <select id="moduleFilter">
                <option value="">All Modules</option>
            </select>
            
            <label>Severity:</label>
            <select id="severityFilter">
                <option value="">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="ERROR">ERROR</option>
                <option value="WARNING">WARNING</option>
                <option value="INFO">INFO</option>
            </select>
            
            <label>Limit:</label>
            <input type="number" id="limitFilter" value="100" min="10" max="1000" step="10">
            
            <button onclick="applyFilters()">Apply Filters</button>
            <button onclick="resetFilters()">Reset</button>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Module</th>
                    <th>Target</th>
                    <th>Details</th>
                    <th>Severity</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody id="findingsTable"></tbody>
        </table>
        
        <div class="auto-refresh">
            ⚡ Auto-refresh: <span id="countdown">30</span>s
        </div>
    </div>
    
    <script>
        const API_BASE = 'api/findings.php';
        let countdown = 30;
        
        // Fetch and display statistics
        async function loadStats() {
            try {
                const response = await fetch(`${API_BASE}?action=stats`);
                const data = await response.json();
                
                if (data.status === 'success') {
                    const stats = data.stats;
                    document.getElementById('stats').innerHTML = `
                        <div class="stat-card">
                            <div class="value">${stats.total.toLocaleString()}</div>
                            <div class="label">Total Findings</div>
                        </div>
                        <div class="stat-card">
                            <div class="value">${stats.modules}</div>
                            <div class="label">Active Modules</div>
                        </div>
                        <div class="stat-card">
                            <div class="value" style="color: #ff4444;">${stats.critical}</div>
                            <div class="label">Critical</div>
                        </div>
                        <div class="stat-card">
                            <div class="value" style="color: #ff8844;">${stats.errors}</div>
                            <div class="label">Errors</div>
                        </div>
                        <div class="stat-card">
                            <div class="value" style="color: #ffcc00;">${stats.warnings}</div>
                            <div class="label">Warnings</div>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }
        
        // Fetch and display modules for filter
        async function loadModules() {
            try {
                const response = await fetch(`${API_BASE}?action=modules`);
                const data = await response.json();
                
                if (data.status === 'success') {
                    const select = document.getElementById('moduleFilter');
                    data.modules.forEach(module => {
                        const option = document.createElement('option');
                        option.value = module;
                        option.textContent = module;
                        select.appendChild(option);
                    });
                }
            } catch (error) {
                console.error('Error loading modules:', error);
            }
        }
        
        // Fetch and display findings
        async function loadFindings() {
            try {
                const module = document.getElementById('moduleFilter').value;
                const limit = document.getElementById('limitFilter').value;
                
                let url = `${API_BASE}?action=findings&limit=${limit}`;
                if (module) url += `&module=${module}`;
                
                const response = await fetch(url);
                const data = await response.json();
                
                if (data.status === 'success') {
                    const tbody = document.getElementById('findingsTable');
                    tbody.innerHTML = data.findings.map(finding => `
                        <tr>
                            <td>${finding.id}</td>
                            <td><span class="module-badge">${finding.module}</span></td>
                            <td>${finding.target}</td>
                            <td>${finding.details}</td>
                            <td class="severity-${finding.severity}">${finding.severity}</td>
                            <td style="color: #888; font-size: 0.9em;">${finding.timestamp}</td>
                        </tr>
                    `).join('');
                }
            } catch (error) {
                console.error('Error loading findings:', error);
            }
        }
        
        // Apply filters
        function applyFilters() {
            loadFindings();
            loadStats();
        }
        
        // Reset filters
        function resetFilters() {
            document.getElementById('moduleFilter').value = '';
            document.getElementById('severityFilter').value = '';
            document.getElementById('limitFilter').value = '100';
            applyFilters();
        }
        
        // Auto-refresh countdown
        setInterval(() => {
            countdown--;
            document.getElementById('countdown').textContent = countdown;
            if (countdown <= 0) {
                countdown = 30;
                loadStats();
                loadFindings();
            }
        }, 1000);
        
        // Initial load
        loadStats();
        loadModules();
        loadFindings();
    </script>
</body>
</html>
