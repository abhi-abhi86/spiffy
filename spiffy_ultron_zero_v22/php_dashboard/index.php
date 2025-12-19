<?php
/**
 * Omega Kernel - Stark Industries Dashboard
 * PHP 8.3 Web Interface for Audit Log Viewing
 */

// Database connection
$db_path = __DIR__ . '/../../ultron_zero.db';
$db = new SQLite3($db_path);

// Get filter parameters
$module_filter = $_GET['module'] ?? '';
$severity_filter = $_GET['severity'] ?? '';
$limit = (int)($_GET['limit'] ?? 100);

// Build query
$query = "SELECT * FROM findings WHERE 1=1";
$params = [];

if ($module_filter) {
    $query .= " AND module = :module";
    $params[':module'] = $module_filter;
}

if ($severity_filter) {
    $query .= " AND severity = :severity";
    $params[':severity'] = $severity_filter;
}

$query .= " ORDER BY timestamp DESC LIMIT :limit";

$stmt = $db->prepare($query);
foreach ($params as $key => $value) {
    $stmt->bindValue($key, $value);
}
$stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);

$results = $stmt->execute();

// Get statistics
$stats_query = "SELECT 
    COUNT(*) as total,
    COUNT(DISTINCT module) as modules,
    COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
    COUNT(CASE WHEN severity = 'ERROR' THEN 1 END) as errors,
    COUNT(CASE WHEN severity = 'WARNING' THEN 1 END) as warnings
FROM findings";
$stats = $db->querySingle($stats_query, true);

// Get module list
$modules_query = "SELECT DISTINCT module FROM findings ORDER BY module";
$modules_result = $db->query($modules_query);
$modules = [];
while ($row = $modules_result->fetchArray(SQLITE3_ASSOC)) {
    $modules[] = $row['module'];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⚡ Omega Kernel - Stark Industries Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #00ff88;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
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
        
        .header p {
            color: #00ccff;
            font-size: 1.1em;
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
        }
        
        .filters h3 {
            margin-bottom: 15px;
            color: #00ccff;
        }
        
        .filter-group {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-group label {
            color: #00ff88;
        }
        
        .filter-group select,
        .filter-group input {
            background: #0a0e27;
            border: 1px solid #00ff88;
            color: #00ff88;
            padding: 8px 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
        }
        
        .filter-group button {
            background: #00ff88;
            color: #0a0e27;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        
        .filter-group button:hover {
            background: #00ccff;
            transform: scale(1.05);
        }
        
        .findings-table {
            background: rgba(0, 255, 136, 0.05);
            border: 1px solid #00ff88;
            border-radius: 8px;
            overflow: hidden;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
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
        
        tr:hover {
            background: rgba(0, 255, 136, 0.1);
        }
        
        .severity-CRITICAL {
            color: #ff4444;
            font-weight: bold;
        }
        
        .severity-ERROR {
            color: #ff8844;
        }
        
        .severity-WARNING {
            color: #ffcc00;
        }
        
        .severity-INFO {
            color: #00ccff;
        }
        
        .module-badge {
            background: rgba(0, 255, 136, 0.2);
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            display: inline-block;
        }
        
        .timestamp {
            color: #888;
            font-size: 0.9em;
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
        
        <div class="stats">
            <div class="stat-card">
                <div class="value"><?= number_format($stats['total']) ?></div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="value"><?= $stats['modules'] ?></div>
                <div class="label">Active Modules</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #ff4444;"><?= $stats['critical'] ?></div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #ff8844;"><?= $stats['errors'] ?></div>
                <div class="label">Errors</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #ffcc00;"><?= $stats['warnings'] ?></div>
                <div class="label">Warnings</div>
            </div>
        </div>
        
        <div class="filters">
            <h3>🔍 FILTERS</h3>
            <form method="GET" class="filter-group">
                <label>Module:</label>
                <select name="module">
                    <option value="">All Modules</option>
                    <?php foreach ($modules as $mod): ?>
                        <option value="<?= htmlspecialchars($mod) ?>" 
                                <?= $module_filter === $mod ? 'selected' : '' ?>>
                            <?= htmlspecialchars($mod) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                
                <label>Severity:</label>
                <select name="severity">
                    <option value="">All Severities</option>
                    <option value="CRITICAL" <?= $severity_filter === 'CRITICAL' ? 'selected' : '' ?>>CRITICAL</option>
                    <option value="ERROR" <?= $severity_filter === 'ERROR' ? 'selected' : '' ?>>ERROR</option>
                    <option value="WARNING" <?= $severity_filter === 'WARNING' ? 'selected' : '' ?>>WARNING</option>
                    <option value="INFO" <?= $severity_filter === 'INFO' ? 'selected' : '' ?>>INFO</option>
                </select>
                
                <label>Limit:</label>
                <input type="number" name="limit" value="<?= $limit ?>" min="10" max="1000" step="10">
                
                <button type="submit">Apply Filters</button>
                <button type="button" onclick="location.href='index.php'">Reset</button>
            </form>
        </div>
        
        <div class="findings-table">
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
                <tbody>
                    <?php while ($row = $results->fetchArray(SQLITE3_ASSOC)): ?>
                    <tr>
                        <td><?= $row['id'] ?></td>
                        <td><span class="module-badge"><?= htmlspecialchars($row['module']) ?></span></td>
                        <td><?= htmlspecialchars($row['target']) ?></td>
                        <td><?= htmlspecialchars($row['details']) ?></td>
                        <td class="severity-<?= $row['severity'] ?>"><?= $row['severity'] ?></td>
                        <td class="timestamp"><?= $row['timestamp'] ?></td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
        
        <div class="auto-refresh">
            ⚡ Auto-refresh: <span id="countdown">30</span>s
        </div>
    </div>
    
    <script>
        // Auto-refresh every 30 seconds
        let countdown = 30;
        setInterval(() => {
            countdown--;
            document.getElementById('countdown').textContent = countdown;
            if (countdown <= 0) {
                location.reload();
            }
        }, 1000);
    </script>
</body>
</html>
