<?php
/**
 * Omega Kernel - REST API
 * JSON endpoint for programmatic access
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$db_path = __DIR__ . '/../../ultron_zero.db';
$db = new SQLite3($db_path);

$action = $_GET['action'] ?? 'findings';

switch ($action) {
    case 'findings':
        $module = $_GET['module'] ?? '';
        $limit = (int)($_GET['limit'] ?? 100);
        
        $query = "SELECT * FROM findings";
        if ($module) {
            $stmt = $db->prepare("SELECT * FROM findings WHERE module = :module ORDER BY timestamp DESC LIMIT :limit");
            $stmt->bindValue(':module', $module);
            $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        } else {
            $stmt = $db->prepare("SELECT * FROM findings ORDER BY timestamp DESC LIMIT :limit");
            $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
        }
        
        $results = $stmt->execute();
        $findings = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $findings[] = $row;
        }
        
        echo json_encode([
            'status' => 'success',
            'count' => count($findings),
            'findings' => $findings
        ], JSON_PRETTY_PRINT);
        break;
    
    case 'stats':
        $stats = $db->querySingle("
            SELECT 
                COUNT(*) as total,
                COUNT(DISTINCT module) as modules,
                COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
                COUNT(CASE WHEN severity = 'ERROR' THEN 1 END) as errors,
                COUNT(CASE WHEN severity = 'WARNING' THEN 1 END) as warnings,
                COUNT(CASE WHEN severity = 'INFO' THEN 1 END) as info
            FROM findings
        ", true);
        
        echo json_encode([
            'status' => 'success',
            'stats' => $stats
        ], JSON_PRETTY_PRINT);
        break;
    
    case 'modules':
        $results = $db->query("SELECT DISTINCT module FROM findings ORDER BY module");
        $modules = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $modules[] = $row['module'];
        }
        
        echo json_encode([
            'status' => 'success',
            'modules' => $modules
        ], JSON_PRETTY_PRINT);
        break;
    
    default:
        echo json_encode([
            'status' => 'error',
            'message' => 'Invalid action'
        ], JSON_PRETTY_PRINT);
}
