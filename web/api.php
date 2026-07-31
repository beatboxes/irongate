<?php
// Suppress ALL warnings/notices from corrupting JSON output
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/irongate-api.log');

// Catch fatal errors too
register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        if (!headers_sent()) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Internal server error']);
        }
    }
});

set_error_handler(function($severity, $message, $file, $line) {
    error_log("Irongate API: [$severity] $message in $file:$line");
    return true;
});

set_exception_handler(function($e) {
    error_log("Irongate API Exception: " . $e->getMessage());
    if (!headers_sent()) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'Server error']);
    }
    exit(1);
});

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, DELETE, PUT');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

$db = new SQLite3('/var/www/irongate/dhcp.db');
// irongate-audit: without a busy timeout, a concurrent php-fpm worker holding
// the write lock made this connection fail immediately, silently dropping
// setting writes and config regeneration under load.
$db->busyTimeout(5000);
$action = $_GET['action'] ?? '';

// Helper functions
function getSetting($db, $key) {
    $stmt = $db->prepare('SELECT value FROM settings WHERE key = ?');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row ? $row['value'] : null;
}

function setSetting($db, $key, $value) {
    $stmt = $db->prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $stmt->bindValue(2, $value, SQLITE3_TEXT);
    return $stmt->execute() ? true : false;
}

function getAllSettings($db) {
    $results = $db->query('SELECT key, value FROM settings');
    $settings = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $settings[$row['key']] = $row['value'];
    }
    return $settings;
}

function cidrToNetmask($cidr) {
    $cidr = intval($cidr);
    $bin = str_repeat('1', $cidr) . str_repeat('0', 32 - $cidr);
    $parts = str_split($bin, 8);
    return implode('.', array_map('bindec', $parts));
}

// Safe wrapper for applyIrongateConfig - prevents PHP warnings from corrupting JSON output
function safeApplyConfig($db) {
    ob_start();
    $result = ['success' => true];
    try {
        $result = applyIrongateConfig($db);
    } catch (Exception $e) {
        $result = ['success' => false, 'error' => $e->getMessage()];
    } catch (Error $e) {
        $result = ['success' => false, 'error' => $e->getMessage()];
    }
    ob_end_clean();
    return $result;
}

function cidrToHosts($cidr) {
    return pow(2, 32 - intval($cidr)) - 2;
}

function getLeases() {
    $leases = [];
    $file = '/var/lib/dnsmasq/dnsmasq.leases';
    if (file_exists($file)) {
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $parts = preg_split('/\s+/', $line);
            if (count($parts) >= 4) {
                $leases[] = [
                    'expires' => date('Y-m-d H:i:s', intval($parts[0])),
                    'expires_unix' => intval($parts[0]),
                    'mac' => strtoupper($parts[1]),
                    'ip' => $parts[2],
                    'hostname' => $parts[3] ?? '*',
                    'client_id' => $parts[4] ?? ''
                ];
            }
        }
    }
    usort($leases, function($a, $b) {
        return ip2long($a['ip']) - ip2long($b['ip']);
    });
    return $leases;
}

function getReservations($db) {
    $results = $db->query('SELECT * FROM reservations ORDER BY ip');
    $reservations = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $reservations[] = $row;
    }
    return $reservations;
}

// Sanitize hostname - replace spaces with hyphens, remove invalid chars
function sanitizeHostname($hostname) {
    $hostname = trim($hostname);
    if (empty($hostname)) return '';
    // Replace spaces with hyphens
    $hostname = str_replace(' ', '-', $hostname);
    // Remove any character that's not alphanumeric or hyphen
    $hostname = preg_replace('/[^a-zA-Z0-9\-]/', '', $hostname);
    // Remove leading/trailing hyphens
    $hostname = trim($hostname, '-');
    // Collapse multiple hyphens
    $hostname = preg_replace('/-+/', '-', $hostname);
    return $hostname;
}

function addReservation($db, $mac, $ip, $hostname, $description) {
    $mac = strtolower(trim($mac));
    $ip = trim($ip);
    $hostname = sanitizeHostname($hostname);
    $stmt = $db->prepare('INSERT OR REPLACE INTO reservations (mac, ip, hostname, description) VALUES (?, ?, ?, ?)');
    $stmt->bindValue(1, $mac, SQLITE3_TEXT);
    $stmt->bindValue(2, $ip, SQLITE3_TEXT);
    $stmt->bindValue(3, $hostname, SQLITE3_TEXT);
    $stmt->bindValue(4, $description, SQLITE3_TEXT);
    $result = $stmt->execute();
    if ($result) {
        syncReservationsToFile($db);
        return true;
    }
    return false;
}

function deleteReservation($db, $id) {
    $stmt = $db->prepare('DELETE FROM reservations WHERE id = ?');
    $stmt->bindValue(1, $id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    syncReservationsToFile($db);
    return $result ? true : false;
}

function syncReservationsToFile($db) {
    $results = $db->query('SELECT * FROM reservations');
    $content = "# Static DHCP Reservations - Auto-generated by Web UI\n";
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $line = "dhcp-host=" . $row['mac'] . "," . $row['ip'];
        $hostname = sanitizeHostname($row['hostname']);
        if (!empty($hostname)) {
            $line .= "," . $hostname;
        }
        $content .= $line . "\n";
    }
    file_put_contents('/etc/dnsmasq.d/reservations.conf', $content);
}

function generateDnsmasqConfig($db) {
    $settings = getAllSettings($db);
    
    $config = "# DHCP Server Configuration\n";
    $config .= "# Auto-generated by Web UI on " . date('Y-m-d H:i:s') . "\n\n";
    
    $interface = $settings['interface'] ?? '';
    if (empty($interface)) {
        $interface = trim(shell_exec("ip route | grep default | awk '{print \$5}' | head -n1"));
    }
    
    $config .= "# Interface\n";
    $config .= "interface=$interface\n";
    // Use bind-dynamic instead of bind-interfaces - more resilient to interface changes
    $config .= "bind-dynamic\n\n";
    
    $config .= "# Disable DNS (DHCP only)\n";
    $config .= "port=0\n\n";
    
    if ($settings['dhcp_enabled'] === 'true' && !empty($settings['range_start']) && !empty($settings['range_end'])) {
        $netmask = cidrToNetmask($settings['cidr'] ?? '24');
        $leaseTime = $settings['lease_time'] ?? '24h';
        
        $config .= "# DHCP Range\n";
        $config .= "dhcp-range={$settings['range_start']},{$settings['range_end']},$netmask,$leaseTime\n\n";
        
        if (!empty($settings['gateway'])) {
            $config .= "# Gateway\n";
            $config .= "dhcp-option=option:router,{$settings['gateway']}\n\n";
        }
        
        $dns = [];
        if (!empty($settings['dns_primary'])) $dns[] = $settings['dns_primary'];
        if (!empty($settings['dns_secondary'])) $dns[] = $settings['dns_secondary'];
        if (!empty($dns)) {
            $config .= "# DNS Servers\n";
            $config .= "dhcp-option=option:dns-server," . implode(',', $dns) . "\n\n";
        }
        
        if (!empty($settings['domain'])) {
            $config .= "# Domain\n";
            $config .= "domain={$settings['domain']}\n\n";
        }
    } else {
        $config .= "# DHCP is disabled - configure via Web UI\n\n";
    }
    
    $config .= "# Lease file\n";
    $config .= "dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases\n\n";
    
    $config .= "# Be authoritative\n";
    $config .= "dhcp-authoritative\n\n";
    
    $config .= "# Logging\n";
    $config .= "log-dhcp\n";
    $config .= "log-facility=/var/log/dnsmasq.log\n\n";
    
    $config .= "# DHCP grace period notification for IronGate\n";
    $config .= "dhcp-script=/opt/irongate/dhcp-notify.sh\n\n";

    $config .= "# Static reservations\n";
    $config .= "conf-dir=/etc/dnsmasq.d/,*.conf\n";

    return $config;
}

// Validate dnsmasq config before applying
function validateConfig($configContent) {
    // Write to temp file and test
    $tempFile = '/tmp/dnsmasq-test-' . time() . '.conf';
    file_put_contents($tempFile, $configContent);
    
    exec("dnsmasq --test --conf-file=$tempFile 2>&1", $output, $retval);
    unlink($tempFile);
    
    return [
        'valid' => ($retval === 0),
        'output' => implode("\n", $output),
        'return_code' => $retval
    ];
}

function applyConfig($db) {
    $config = generateDnsmasqConfig($db);
    
    // Validate config first
    $validation = validateConfig($config);
    if (!$validation['valid']) {
        return [
            'success' => false,
            'error' => 'Config validation failed: ' . $validation['output'],
            'stage' => 'validation'
        ];
    }
    
    // Write the config
    file_put_contents('/etc/dnsmasq.conf', $config);
    
    // Stop current service gracefully
    exec('sudo systemctl stop dnsmasq 2>&1', $stopOutput, $stopRetval);
    usleep(500000); // Wait 500ms
    
    // Start the service
    exec('sudo systemctl start dnsmasq 2>&1', $startOutput, $startRetval);
    
    if ($startRetval !== 0) {
        // Get the actual error from journalctl
        exec('journalctl -u dnsmasq -n 20 --no-pager 2>&1', $journalOutput);
        return [
            'success' => false,
            'error' => 'Service start failed',
            'output' => implode("\n", $startOutput),
            'journal' => implode("\n", $journalOutput),
            'stage' => 'start'
        ];
    }
    
    return ['success' => true];
}

function getServiceStatus() {
    exec('systemctl is-active dnsmasq 2>&1', $output, $retval);
    $active = ($retval === 0);
    
    $uptime = '';
    $lastError = '';
    if ($active) {
        $uptime = trim(shell_exec("systemctl show dnsmasq --property=ActiveEnterTimestamp | cut -d'=' -f2"));
    } else {
        // Get last error from journal
        exec('journalctl -u dnsmasq -n 10 --no-pager 2>&1', $journalOutput);
        $lastError = implode("\n", $journalOutput);
    }
    
    return [
        'running' => $active,
        'status' => $active ? 'running' : 'stopped',
        'since' => $uptime,
        'last_error' => $lastError
    ];
}

function getSystemInfo() {
    $interface = trim(shell_exec("ip route | grep default | awk '{print \$5}' | head -n1"));
    $ip = trim(shell_exec("ip -4 addr show $interface | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1"));
    $cidr = trim(shell_exec("ip -4 addr show $interface | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+' | head -n1 | cut -d'/' -f2"));
    $gateway = trim(shell_exec("ip route | grep default | awk '{print \$3}' | head -n1"));
    $mac = trim(shell_exec("ip link show $interface | grep -oP '(?<=link/ether\s)[a-f0-9:]+' | head -n1"));
    $hostname = gethostname();
    
    // Get all interfaces
    $interfaces = [];
    exec("ip -o link show | awk -F': ' '{print \$2}' | grep -v lo", $ifaceList);
    foreach ($ifaceList as $iface) {
        $iface = trim(explode('@', $iface)[0]);
        $ifaceIp = trim(shell_exec("ip -4 addr show $iface 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1"));
        $interfaces[] = [
            'name' => $iface,
            'ip' => $ifaceIp ?: 'No IP',
            'current' => ($iface === $interface)
        ];
    }
    
    return [
        'hostname' => $hostname,
        'interface' => $interface,
        'interfaces' => $interfaces,
        'ip' => $ip,
        'cidr' => $cidr,
        'mac' => $mac,
        'gateway' => $gateway,
        'uptime' => trim(shell_exec('uptime -p'))
    ];
}

function getRecentLogs($lines = 100) {
    $logs = [];
    $debug = [];
    $lines = max(1, min(1000, intval($lines)));
    $logFile = '/var/log/dnsmasq.log';
    $syslogFile = '/var/log/syslog';
    
    // Method 1: Read the dedicated log file directly (most likely to work)
    if (file_exists($logFile)) {
        $debug[] = "Log file exists: $logFile";
        $fileSize = filesize($logFile);
        $debug[] = "File size: $fileSize bytes";
        
        if ($fileSize > 0) {
            // Try tail command first (efficient for large files)
            $tailCmd = "/usr/bin/tail -n $lines " . escapeshellarg($logFile) . " 2>&1";
            $tailOutput = [];
            exec($tailCmd, $tailOutput, $tailRet);
            $debug[] = "tail returned: $tailRet, lines: " . count($tailOutput);
            if (count($tailOutput) > 0) {
                foreach ($tailOutput as $line) {
                    $line = trim($line);
                    if (strlen($line) > 0) {
                        $logs[] = htmlspecialchars($line);
                    }
                }
                if (count($logs) > 0) {
                    return array_reverse($logs);
                }
            }

            // Fall back to direct read
            if (is_readable($logFile)) {
                $content = @file_get_contents($logFile);
                if ($content !== false && strlen($content) > 0) {
                    $allLines = explode("\n", $content);
                    $allLines = array_filter($allLines, function($l) { return strlen(trim($l)) > 0; });
                    if (count($allLines) > 0) {
                        $recentLines = array_slice($allLines, -$lines);
                        foreach ($recentLines as $line) {
                            $logs[] = htmlspecialchars(trim($line));
                        }
                        return array_reverse($logs);
                    }
                }
            }
        } else {
            $debug[] = "Log file is empty";
        }
    } else {
        $debug[] = "Log file does not exist: $logFile";
    }
    
    // Method 2: Try journalctl (may require group membership)
    $journalCmd = "/usr/bin/journalctl -u dnsmasq -n $lines --no-pager 2>&1";
    $journalOutput = [];
    exec($journalCmd, $journalOutput, $journalRet);
    $debug[] = "journalctl returned: $journalRet, lines: " . count($journalOutput);
    
    if ($journalRet === 0 && count($journalOutput) > 0) {
        foreach ($journalOutput as $line) {
            $line = trim($line);
            // Skip journal metadata lines
            if (strlen($line) > 0 && 
                strpos($line, '-- No entries --') === false && 
                strpos($line, '-- Journal begins') === false &&
                strpos($line, '-- Logs begin') === false) {
                $logs[] = htmlspecialchars($line);
            }
        }
        if (count($logs) > 0) {
            return array_reverse($logs);
        }
    }
    
    // Method 3: Try syslog
    if (file_exists($syslogFile) && is_readable($syslogFile)) {
        $debug[] = "Trying syslog";
        $grepCmd = "/usr/bin/grep -i dnsmasq " . escapeshellarg($syslogFile) . " 2>/dev/null | /usr/bin/tail -n $lines";
        $syslogOutput = [];
        exec($grepCmd, $syslogOutput, $syslogRet);
        $debug[] = "syslog grep returned: $syslogRet, lines: " . count($syslogOutput);
        
        if (count($syslogOutput) > 0) {
            foreach ($syslogOutput as $line) {
                $line = trim($line);
                if (strlen($line) > 0) {
                    $logs[] = htmlspecialchars($line);
                }
            }
            if (count($logs) > 0) {
                return array_reverse($logs);
            }
        }
    }
    
    // Method 4: Check systemctl status output for recent activity
    $statusOutput = [];
    exec("/bin/systemctl status dnsmasq 2>&1 | tail -20", $statusOutput, $statusRet);
    if (count($statusOutput) > 0) {
        foreach ($statusOutput as $line) {
            $line = trim($line);
            if (strlen($line) > 0 && (strpos($line, 'dnsmasq') !== false || strpos($line, 'DHCP') !== false)) {
                $logs[] = htmlspecialchars($line);
            }
        }
        if (count($logs) > 0) {
            return array_reverse($logs);
        }
    }
    
    // Return debug info if no logs found
    $noLogsMsg = ['No DHCP logs found. Debug info:'];
    foreach ($debug as $d) {
        $noLogsMsg[] = "  - $d";
    }
    $noLogsMsg[] = '';
    $noLogsMsg[] = 'Possible reasons:';
    $noLogsMsg[] = '  - No DHCP requests have been made yet';
    $noLogsMsg[] = '  - Service is not running';
    $noLogsMsg[] = '  - Log file permissions issue';
    
    return $noLogsMsg;
}

// Get diagnostic info for troubleshooting
function getDiagnostics() {
    $diag = [];
    
    // Check dnsmasq config syntax
    exec('dnsmasq --test 2>&1', $testOutput, $testRetval);
    $diag['config_valid'] = ($testRetval === 0);
    $diag['config_test'] = implode("\n", $testOutput);
    
    // Check if port 67 is in use by something else
    exec('ss -ulnp | grep :67 2>&1', $portOutput);
    $diag['port_67_status'] = implode("\n", $portOutput);
    
    // Check interface status
    $interface = trim(shell_exec("grep '^interface=' /etc/dnsmasq.conf | cut -d'=' -f2"));
    $diag['configured_interface'] = $interface;
    exec("ip link show $interface 2>&1", $ifaceOutput, $ifaceRetval);
    $diag['interface_exists'] = ($ifaceRetval === 0);
    $diag['interface_status'] = implode("\n", $ifaceOutput);
    
    // Check file permissions (from dnsmasq's perspective, not www-data's)
    $dnsmasqUser = posix_getpwnam('dnsmasq');
    $dnsmasqUid = $dnsmasqUser ? $dnsmasqUser['uid'] : null;
    
    $leasesStat = @stat('/var/lib/dnsmasq/dnsmasq.leases');
    $diag['leases_writable'] = $leasesStat && $dnsmasqUid !== null && $leasesStat['uid'] === $dnsmasqUid && ($leasesStat['mode'] & 0200);
    
    $logStat = @stat('/var/log/dnsmasq.log');
    $diag['log_writable'] = $logStat && $dnsmasqUid !== null && $logStat['uid'] === $dnsmasqUid && ($logStat['mode'] & 0200);
    
    // Get recent journal errors
    exec('journalctl -u dnsmasq -p err -n 10 --no-pager 2>&1', $errOutput);
    $diag['recent_errors'] = implode("\n", $errOutput);
    
    // Get service status detail
    exec('systemctl status dnsmasq 2>&1', $statusOutput);
    $diag['service_status'] = implode("\n", $statusOutput);
    
    return $diag;
}

// Fix common issues automatically
function autoRepair() {
    $repairs = [];
    
    // Ensure lease file exists and is writable
    if (!file_exists('/var/lib/dnsmasq/dnsmasq.leases')) {
        touch('/var/lib/dnsmasq/dnsmasq.leases');
        chmod('/var/lib/dnsmasq/dnsmasq.leases', 0644);
        $repairs[] = 'Created lease file';
    }
    
    // Ensure log file exists and is writable
    if (!file_exists('/var/log/dnsmasq.log')) {
        touch('/var/log/dnsmasq.log');
        chmod('/var/log/dnsmasq.log', 0644);
        $repairs[] = 'Created log file';
    }
    
    // Fix common permission issues
    exec('sudo chown dnsmasq:nogroup /var/lib/dnsmasq/dnsmasq.leases 2>&1');
    exec('sudo chmod 644 /var/lib/dnsmasq/dnsmasq.leases 2>&1');
    exec('sudo chmod 664 /var/log/dnsmasq.log 2>&1');
    $repairs[] = 'Fixed file permissions';
    
    // Only kill dnsmasq if it is in a failed/stuck state, not if running fine
    exec('systemctl is-active dnsmasq 2>&1', $activeCheck, $activeRet);
    if ($activeRet !== 0) {
        exec('logger -t irongate-autorepair "dnsmasq is-active returned '.$activeRet.', killing stale processes"');
        exec('sudo pkill -9 dnsmasq 2>&1');
        usleep(500000);
        $repairs[] = 'Killed stale dnsmasq processes';
    } else {
        exec('logger -t irongate-autorepair "dnsmasq is-active returned 0, skipping kill"');
        $repairs[] = 'Service already running, skipped kill';
    }
    
    // Try to start the service
    exec('sudo systemctl start dnsmasq 2>&1', $output, $retval);
    
    if ($retval === 0) {
        $repairs[] = 'Service started successfully';
        return ['success' => true, 'repairs' => $repairs];
    } else {
        exec('journalctl -u dnsmasq -n 10 --no-pager 2>&1', $journalOutput);
        $repairs[] = 'Service failed to start';
        return [
            'success' => false,
            'repairs' => $repairs,
            'error' => implode("\n", $journalOutput)
        ];
    }
}

// API Routes
switch ($action) {
    case 'system':
        echo json_encode(['success' => true, 'data' => getSystemInfo()]);
        break;
    
    case 'status':
        echo json_encode(['success' => true, 'data' => getServiceStatus()]);
        break;
    
    case 'settings':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            
            // Validate lease_time format (dnsmasq format: 30m, 24h, 7d, 1w, infinite, or raw seconds)
            if (isset($data['lease_time'])) {
                $lt = trim($data['lease_time']);
                if (!preg_match('/^(\d+[smhdw]?|infinite)$/i', $lt)) {
                    echo json_encode(['success' => false, 'error' => 'Invalid lease time format. Use: 30m, 24h, 7d, 1w, or infinite']);
                    exit;
                }
                $data['lease_time'] = strtolower($lt);
            }
            
            foreach ($data as $key => $value) {
                setSetting($db, $key, $value);
            }
            $result = applyConfig($db);
            if (is_array($result) && isset($result['success'])) {
                echo json_encode($result);
            } else {
                echo json_encode(['success' => $result, 'applied' => $result]);
            }
        } else {
            echo json_encode(['success' => true, 'data' => getAllSettings($db)]);
        }
        break;
    
    case 'apply':
        $result = applyConfig($db);
        echo json_encode($result);
        break;
    
    case 'leases':
        echo json_encode(['success' => true, 'data' => getLeases()]);
        break;
    
    case 'reservations':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $result = addReservation($db, $data['mac'], $data['ip'], $data['hostname'] ?? '', $data['description'] ?? '');
            if ($result) {
                $applyResult = applyConfig($db);
                echo json_encode(['success' => true, 'applied' => $applyResult]);
            } else {
                echo json_encode(['success' => false]);
            }
        } elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $id = $_GET['id'] ?? 0;
            $result = deleteReservation($db, $id);
            if ($result) {
                $applyResult = applyConfig($db);
                echo json_encode(['success' => true, 'applied' => $applyResult]);
            } else {
                echo json_encode(['success' => false]);
            }
        } else {
            echo json_encode(['success' => true, 'data' => getReservations($db)]);
        }
        break;
    
    case 'logs':
        $lines = intval($_GET['lines'] ?? 100);
        echo json_encode(['success' => true, 'data' => getRecentLogs($lines)]);
        break;
    
    case 'restart':
        // Stop first
        exec('sudo systemctl stop dnsmasq 2>&1');
        usleep(500000);
        // Start
        exec('sudo systemctl start dnsmasq 2>&1', $output, $retval);
        if ($retval !== 0) {
            exec('journalctl -u dnsmasq -n 20 --no-pager 2>&1', $journalOutput);
            echo json_encode([
                'success' => false,
                'output' => implode("\n", $output),
                'journal' => implode("\n", $journalOutput)
            ]);
        } else {
            echo json_encode(['success' => true, 'output' => implode("\n", $output)]);
        }
        break;
    
    case 'stop':
        exec('sudo systemctl stop dnsmasq 2>&1', $output, $retval);
        echo json_encode(['success' => $retval === 0]);
        break;
    
    case 'start':
        exec('sudo systemctl start dnsmasq 2>&1', $output, $retval);
        if ($retval !== 0) {
            exec('journalctl -u dnsmasq -n 20 --no-pager 2>&1', $journalOutput);
            echo json_encode([
                'success' => false,
                'output' => implode("\n", $output),
                'journal' => implode("\n", $journalOutput)
            ]);
        } else {
            echo json_encode(['success' => true]);
        }
        break;
    
    case 'diagnostics':
        echo json_encode(['success' => true, 'data' => getDiagnostics()]);
        break;
    
    case 'repair':
        echo json_encode(autoRepair());
        break;
    
    case 'validate':
        $config = generateDnsmasqConfig($db);
        $result = validateConfig($config);
        echo json_encode(['success' => true, 'data' => $result]);
        break;
    
    //==========================================================================
    // IRONGATE NETWORK ISOLATION API
    //==========================================================================
    
    case 'irongate_status':
        $enabled = getSetting($db, 'irongate_enabled') === 'true';
        $mode = getSetting($db, 'irongate_mode') ?? 'single';
        exec('systemctl is-active irongate 2>&1', $svcOutput, $svcRet);
        $serviceActive = ($svcRet === 0);
        
        echo json_encode([
            'success' => true,
            'data' => [
                'enabled' => $enabled,
                'mode' => $mode,
                'service_running' => $serviceActive,
                'isolated_interface' => getSetting($db, 'irongate_isolated_interface'),
                'bridge_ip' => getSetting($db, 'irongate_bridge_ip'),
                'layers' => [
                    'arp_defense' => getSetting($db, 'irongate_arp_defense') !== 'false',
                    'ipv6_ra' => getSetting($db, 'irongate_ipv6_ra') !== 'false',
                    'gateway_takeover' => getSetting($db, 'irongate_gateway_takeover') !== 'false',
                    'bypass_detection' => getSetting($db, 'irongate_bypass_detection') !== 'false',
                    'firewall' => getSetting($db, 'irongate_firewall') !== 'false'
                ]
            ]
        ]);
        break;
    
    case 'irongate_settings':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            foreach ($data as $key => $value) {
                // irongate-audit: the Midnight read path needs no key material.
                // Refuse to persist secret-bearing keys so a mnemonic can never
                // re-enter the settings table (and from there an unauthenticated
                // read and a world-readable config.yaml).
                if (preg_match('/mnemonic|private_key|secret|passphrase|seed/i', $key)) {
                    continue;
                }
                if (strpos($key, 'irongate_') === 0 || strpos($key, 'blockchain_') === 0) {
                    setSetting($db, $key, $value);
                }
            }
            $result = safeApplyConfig($db);
            echo json_encode($result);
        } else {
            $settings = [];
            foreach (['irongate_enabled', 'irongate_mode', 'irongate_isolated_interface',
                      'irongate_bridge_ip', 'irongate_bridge_dhcp_start', 'irongate_bridge_dhcp_end',
                      'irongate_arp_defense', 'irongate_ipv6_ra', 'irongate_gateway_takeover',
                      'irongate_bypass_detection', 'irongate_firewall',
                      'blockchain_enabled', 'blockchain_network',
                      'blockchain_contract_address', 'blockchain_indexer_url',
                      'blockchain_cache_ttl', 'blockchain_fallback_allow',
                      'blockchain_audit_logging', 'blockchain_allow_rogue_devices'] as $key) {
                $settings[$key] = getSetting($db, $key);
            }
            echo json_encode(['success' => true, 'data' => $settings]);
        }
        break;
    
    case 'irongate_interfaces':
        $interfaces = [];
        $mainIface = getSetting($db, 'interface') ?: trim(shell_exec("ip route | grep default | awk '{print \$5}' | head -n1"));
        exec("ls /sys/class/net 2>/dev/null", $ifaceList);
        foreach ($ifaceList as $iface) {
            $iface = trim($iface);
            if (in_array($iface, ['lo', 'docker0', 'br-irongate', 'br0'])) continue;
            $isUsb = (strpos($iface, 'enx') === 0 || strpos($iface, 'usb') === 0);
            if (!$isUsb && file_exists("/sys/class/net/$iface/device/uevent")) {
                $uevent = @file_get_contents("/sys/class/net/$iface/device/uevent");
                $isUsb = (stripos($uevent, 'usb') !== false);
            }
            $mac = trim(@file_get_contents("/sys/class/net/$iface/address") ?: '');
            $state = trim(@file_get_contents("/sys/class/net/$iface/operstate") ?: 'unknown');
            $interfaces[] = [
                'name' => $iface,
                'mac' => $mac,
                'state' => $state,
                'is_usb' => $isUsb,
                'is_main' => ($iface === $mainIface)
            ];
        }
        echo json_encode(['success' => true, 'data' => $interfaces]);
        break;
    
    case 'irongate_toggle':
        $data = json_decode(file_get_contents('php://input'), true);
        $enable = $data['enabled'] ?? false;
        setSetting($db, 'irongate_enabled', $enable ? 'true' : 'false');
        
        if ($enable) {
            $result = safeApplyConfig($db);
        } else {
            exec('sudo systemctl stop irongate >/dev/null 2>&1 &');
            $result = ['success' => true, 'message' => 'Irongate disabled'];
        }
        echo json_encode($result);
        break;
    
    case 'irongate_apply':
        $result = safeApplyConfig($db);
        echo json_encode($result);
        break;
    
    case 'irongate_logs':
        $lines = intval($_GET['lines'] ?? 50);
        $logs = [];
        exec("sudo journalctl -u irongate -n $lines --no-pager 2>&1", $journalOutput);
        foreach ($journalOutput as $line) {
            $line = trim($line);
            if (!empty($line) && strpos($line, '-- No entries') === false) {
                $logs[] = htmlspecialchars($line);
            }
        }
        echo json_encode(['success' => true, 'data' => array_reverse($logs)]);
        break;

    case 'device_groups':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $name = trim($data['name'] ?? '');

            // Validate name - cannot use built-in group names
            $reserved = ['isolated', 'servers', 'trusted'];
            if (in_array(strtolower($name), $reserved)) {
                echo json_encode(['success' => false, 'error' => 'Cannot use reserved group name']);
                break;
            }

            if (empty($name)) {
                echo json_encode(['success' => false, 'error' => 'Group name is required']);
                break;
            }

            $stmt = $db->prepare('INSERT OR REPLACE INTO device_groups (name, color, icon, description, lan_access, can_access_groups) VALUES (?, ?, ?, ?, ?, ?)');
            $stmt->bindValue(1, $name, SQLITE3_TEXT);
            $stmt->bindValue(2, $data['color'] ?? '#6c757d', SQLITE3_TEXT);
            $stmt->bindValue(3, $data['icon'] ?? '📁', SQLITE3_TEXT);
            $stmt->bindValue(4, $data['description'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(5, $data['lan_access'] ?? 'none', SQLITE3_TEXT);
            $stmt->bindValue(6, json_encode($data['can_access_groups'] ?? []), SQLITE3_TEXT);
            $result = $stmt->execute();

            if ($result) {
                safeApplyConfig($db);
            }
            echo json_encode(['success' => $result ? true : false]);
        } elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $id = $_GET['id'] ?? 0;
            $name = $_GET['name'] ?? '';

            // First get the group name if deleting by ID
            if ($id) {
                $stmt = $db->prepare('SELECT name FROM device_groups WHERE id = ?');
                $stmt->bindValue(1, $id, SQLITE3_INTEGER);
                $result = $stmt->execute();
                $row = $result->fetchArray(SQLITE3_ASSOC);
                if ($row) {
                    $name = $row['name'];
                }
            }

            // Move all devices in this group to 'isolated'
            if ($name) {
                $stmt = $db->prepare('UPDATE irongate_devices SET zone = ? WHERE zone = ?');
                $stmt->bindValue(1, 'isolated', SQLITE3_TEXT);
                $stmt->bindValue(2, $name, SQLITE3_TEXT);
                $stmt->execute();
            }

            // Delete the group
            if ($id) {
                $stmt = $db->prepare('DELETE FROM device_groups WHERE id = ?');
                $stmt->bindValue(1, $id, SQLITE3_INTEGER);
            } else {
                $stmt = $db->prepare('DELETE FROM device_groups WHERE name = ?');
                $stmt->bindValue(1, $name, SQLITE3_TEXT);
            }
            $result = $stmt->execute();

            if ($result) {
                safeApplyConfig($db);
            }
            echo json_encode(['success' => $result ? true : false]);
        } else {
            // GET - return all custom groups plus built-in groups
            $results = $db->query('SELECT * FROM device_groups ORDER BY name');
            $groups = [];

            // Add built-in groups first
            $groups[] = [
                'id' => 0,
                'name' => 'isolated',
                'color' => '#e94560',
                'icon' => '🔴',
                'description' => 'Internet only, no LAN access',
                'lan_access' => 'none',
                'can_access_groups' => [],
                'builtin' => true
            ];
            $groups[] = [
                'id' => 0,
                'name' => 'servers',
                'color' => '#ffc107',
                'icon' => '🟡',
                'description' => 'Can communicate with other servers',
                'lan_access' => 'servers',
                'can_access_groups' => ['servers'],
                'builtin' => true
            ];
            $groups[] = [
                'id' => 0,
                'name' => 'trusted',
                'color' => '#00bf63',
                'icon' => '🟢',
                'description' => 'Full network access',
                'lan_access' => 'full',
                'can_access_groups' => [],
                'builtin' => true
            ];

            // Add custom groups
            while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                $row['can_access_groups'] = json_decode($row['can_access_groups'] ?? '[]', true) ?: [];
                $row['builtin'] = false;
                $groups[] = $row;
            }

            echo json_encode(['success' => true, 'data' => $groups]);
        }
        break;

    case 'irongate_devices':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $stmt = $db->prepare('INSERT OR REPLACE INTO irongate_devices (mac, ip, hostname, zone) VALUES (?, ?, ?, ?)');
            $stmt->bindValue(1, strtolower($data['mac']), SQLITE3_TEXT);
            $stmt->bindValue(2, $data['ip'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(3, $data['hostname'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(4, $data['zone'] ?? 'isolated', SQLITE3_TEXT);
            $result = $stmt->execute();
            if ($result) {
                safeApplyConfig($db);
            }
            echo json_encode(['success' => $result ? true : false]);
        } elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $id = $_GET['id'] ?? 0;
            $stmt = $db->prepare('DELETE FROM irongate_devices WHERE id = ?');
            $stmt->bindValue(1, $id, SQLITE3_INTEGER);
            $result = $stmt->execute();
            if ($result) {
                safeApplyConfig($db);
            }
            echo json_encode(['success' => $result ? true : false]);
        } else {
            $results = $db->query('SELECT * FROM irongate_devices ORDER BY zone, ip');
            $devices = [];
            while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
                $devices[] = $row;
            }
            echo json_encode(['success' => true, 'data' => $devices]);
        }
        break;
    
    case 'irongate_diag':
        // Diagnostic info for troubleshooting
        $diag = [];
        
        // 1. Check devices with IPs
        $results = $db->query('SELECT * FROM irongate_devices WHERE ip IS NOT NULL AND ip != ""');
        $devicesWithIp = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $devicesWithIp[] = $row;
        }
        $diag['devices_with_ip'] = $devicesWithIp;
        $diag['devices_without_ip_warning'] = count($devicesWithIp) === 0 ? 
            'WARNING: No devices have IPs set! Firewall rules will not work.' : null;
        
        // 2. IP forwarding status
        $ipForward = trim(shell_exec('cat /proc/sys/net/ipv4/ip_forward 2>/dev/null'));
        $diag['ip_forward'] = $ipForward === '1' ? 'enabled' : 'DISABLED';
        
        // 3. nftables rules
        $nftRules = shell_exec('nft list table inet irongate 2>&1');
        $diag['nftables'] = $nftRules ?: 'No irongate table found';
        
        // 4. ARP cache
        $arpCache = shell_exec('ip neigh show 2>/dev/null | head -20');
        $diag['arp_cache'] = $arpCache;
        
        // 5. Service status
        exec('systemctl status irongate 2>&1', $svcStatus);
        $diag['service_status'] = implode("\n", array_slice($svcStatus, 0, 15));
        
        // 6. Recent logs
        $logs = shell_exec('sudo journalctl -u irongate -n 30 --no-pager 2>&1');
        $diag['recent_logs'] = $logs;
        
        // 7. Config file
        $config = @file_get_contents('/etc/irongate/config.yaml');
        $diag['config'] = $config ?: 'Config file not found';
        
        echo json_encode(['success' => true, 'data' => $diag]);
        break;
    
    case 'update_check':
        // Check for updates from GitHub using commit hash
        $currentCommit = getSetting($db, 'installed_commit') ?: 'unknown';
        $githubApi = 'https://api.github.com/repos/beatboxes/irongate/commits/main';
        
        // Fetch latest commit from GitHub API
        $ctx = stream_context_create([
            'http' => [
                'timeout' => 10,
                'header' => 'User-Agent: Irongate-Updater'
            ]
        ]);
        $response = @file_get_contents($githubApi, false, $ctx);
        
        if ($response === false) {
            echo json_encode(['success' => false, 'error' => 'Could not reach GitHub API']);
            break;
        }
        
        $data = json_decode($response, true);
        if (!isset($data['sha'])) {
            echo json_encode(['success' => false, 'error' => 'Invalid response from GitHub']);
            break;
        }
        
        $remoteCommit = substr($data['sha'], 0, 7);
        $commitMessage = $data['commit']['message'] ?? '';
        $commitDate = $data['commit']['committer']['date'] ?? '';
        $updateAvailable = ($currentCommit !== $remoteCommit && $currentCommit !== 'unknown' && $currentCommit !== 'local');
        
        // Update last check time
        setSetting($db, 'last_update_check', date('Y-m-d H:i:s'));
        
        echo json_encode([
            'success' => true,
            'current_commit' => $currentCommit,
            'remote_commit' => $remoteCommit,
            'update_available' => $updateAvailable,
            'commit_message' => $commitMessage,
            'commit_date' => $commitDate,
            'last_check' => date('Y-m-d H:i:s')
        ]);
        break;
    
    case 'update_settings':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            if (isset($data['auto_update_enabled'])) {
                setSetting($db, 'auto_update_enabled', $data['auto_update_enabled'] ? 'true' : 'false');
                
                // Enable/disable the auto-update timer
                if ($data['auto_update_enabled']) {
                    exec('sudo systemctl enable irongate-updater.timer 2>&1');
                    exec('sudo systemctl start irongate-updater.timer 2>&1');
                } else {
                    exec('sudo systemctl stop irongate-updater.timer 2>&1');
                    exec('sudo systemctl disable irongate-updater.timer 2>&1');
                }
            }
            echo json_encode(['success' => true]);
        } else {
            echo json_encode([
                'success' => true,
                'data' => [
                    'auto_update_enabled' => getSetting($db, 'auto_update_enabled') === 'true',
                    'installed_commit' => getSetting($db, 'installed_commit') ?: 'unknown',
                    'last_update_check' => getSetting($db, 'last_update_check') ?: 'Never'
                ]
            ]);
        }
        break;
    
    case 'update_now':
        // irongate-audit: this action runs a downloaded script as root. As a
        // GET it was reachable by any link, prefetch or cross-origin form,
        // turning a page visit into root code execution. Require POST.
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['success' => false, 'error' => 'update_now requires POST']);
            break;
        }
        // Perform update
        $repoRaw = 'https://raw.githubusercontent.com/beatboxes/irongate/main';
        $githubApi = 'https://api.github.com/repos/beatboxes/irongate/commits/main';
        $scriptPath = '/tmp/irongate-update.sh';
        
        // First, get the commit hash we're updating TO
        $ctx = stream_context_create(['http' => ['timeout' => 10, 'header' => 'User-Agent: Irongate-Updater']]);
        $commitData = @file_get_contents($githubApi, false, $ctx);
        $targetCommit = 'unknown';
        if ($commitData) {
            $json = json_decode($commitData, true);
            if (isset($json['sha'])) {
                $targetCommit = substr($json['sha'], 0, 7);
            }
        }
        
        // Download the latest install script
        $ctx = stream_context_create(['http' => ['timeout' => 30, 'header' => 'User-Agent: Irongate-Updater']]);
        $script = @file_get_contents("$repoRaw/irongate-install.sh", false, $ctx);
        
        if ($script === false) {
            echo json_encode(['success' => false, 'error' => 'Failed to download update']);
            break;
        }
        
        // Save commit hash BEFORE running update (in case script fails to set it)
        setSetting($db, 'installed_commit', $targetCommit);
        
        // Save and execute
        file_put_contents($scriptPath, $script);
        chmod($scriptPath, 0755);
        
        // Create log file with proper permissions first
        exec("sudo touch /var/log/irongate-update.log");
        exec("sudo chown www-data /var/log/irongate-update.log");
        
        // Run update in background
        exec("sudo bash $scriptPath > /var/log/irongate-update.log 2>&1 &");
        
        echo json_encode([
            'success' => true,
            'message' => 'Update started. The page will reload when complete.',
            'log' => '/var/log/irongate-update.log',
            'target_commit' => $targetCommit
        ]);
        break;
    
    case 'update_log':
        $log = @file_get_contents('/var/log/irongate-update.log');
        echo json_encode(['success' => true, 'data' => $log ?: 'No update log available']);
        break;
    
    default:
        echo json_encode(['error' => 'Unknown action', 'available' => [
            'system', 'status', 'settings', 'apply', 'leases', 
            'reservations', 'logs', 'restart', 'stop', 'start',
            'diagnostics', 'repair', 'validate',
            'irongate_status', 'irongate_settings', 'irongate_interfaces',
            'irongate_toggle', 'irongate_apply', 'irongate_logs', 'irongate_devices', 'device_groups',
            'update_check', 'update_settings', 'update_now', 'update_log'
        ]]);
}

// irongate-audit: emit an arbitrary value as a safe YAML scalar.
// JSON string escaping is a valid subset of YAML 1.2 double-quoted style, so
// this neutralises the newlines, quotes and backslashes that previously let a
// stored setting (group name, description, zone, interface...) inject arbitrary
// YAML into /etc/irongate/config.yaml. A crafted value could add or rewrite
// engine directives, or make the file unparseable so the engine died on restart.
function yamlScalar($v) {
    return json_encode((string)$v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

// Irongate config generator
function applyIrongateConfig($db) {
    $settings = getAllSettings($db);
    $enabled = ($settings['irongate_enabled'] ?? 'false') === 'true';
    
    if (!$enabled) {
        exec('sudo systemctl stop irongate >/dev/null 2>&1 &');
        return ['success' => true, 'message' => 'Irongate disabled'];
    }
    
    $mode = $settings['irongate_mode'] ?? 'single';
    $interface = $settings['interface'] ?: trim(shell_exec("ip route | grep default | awk '{print \$5}' | head -n1"));
    $gateway = $settings['gateway'] ?: trim(shell_exec("ip route | grep default | awk '{print \$3}' | head -n1"));
    $localIp = trim(shell_exec("ip -4 addr show " . escapeshellarg($interface) . " 2>/dev/null | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | head -n1"));
    $localMac = trim(shell_exec("ip link show " . escapeshellarg($interface) . " 2>/dev/null | awk '/ether/ {print \$2}'"));
    
    // Get gateway MAC - try ARP cache first, then arping
    $gatewayMac = trim(shell_exec("ip neigh show | grep " . escapeshellarg($gateway . ' ') . " | awk '{print \$5}' | head -n1"));
    if (empty($gatewayMac)) {
        exec("arping -c 1 -I " . escapeshellarg($interface) . " "
             . escapeshellarg($gateway) . " 2>/dev/null", $arpOutput);
        $gatewayMac = trim(shell_exec("ip neigh show | grep " . escapeshellarg($gateway . ' ') . " | awk '{print \$5}' | head -n1"));
    }
    
    // Generate YAML config
    $config = "# Irongate Configuration\n";
    $config .= "# Generated: " . date('Y-m-d H:i:s') . "\n\n";
    $config .= "network:\n";
    $config .= "  interface: " . yamlScalar($interface) . "\n";
    $config .= "  local_ip: " . yamlScalar($localIp) . "\n";
    $config .= "  local_mac: " . yamlScalar($localMac) . "\n";
    $config .= "  gateway_ip: " . yamlScalar($gateway) . "\n";
    $config .= "  gateway_mac: " . yamlScalar($gatewayMac) . "\n\n";
    
    $config .= "mode: " . yamlScalar($mode) . "\n\n";
    
    if ($mode === 'dual') {
        $config .= "bridge:\n";
        $config .= "  enabled: true\n";
        $config .= "  isolated_interface: " . yamlScalar($settings['irongate_isolated_interface'] ?? '') . "\n";
        $config .= "  bridge_name: \"br-irongate\"\n";
        $config .= "  bridge_ip: " . yamlScalar($settings['irongate_bridge_ip'] ?? '10.99.0.1') . "\n";
        $config .= "  bridge_netmask: \"255.255.0.0\"\n";
        $config .= "  dhcp_start: " . yamlScalar($settings['irongate_bridge_dhcp_start'] ?? '10.99.1.1') . "\n";
        $config .= "  dhcp_end: " . yamlScalar($settings['irongate_bridge_dhcp_end'] ?? '10.99.255.254') . "\n";
        $config .= "  port_isolation: true\n\n";
    }
    
    $config .= "layers:\n";
    $config .= "  arp_defense: " . (($settings['irongate_arp_defense'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  ipv6_ra: " . (($settings['irongate_ipv6_ra'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  gateway_takeover: " . (($settings['irongate_gateway_takeover'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  bypass_detection: " . (($settings['irongate_bypass_detection'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  firewall: " . (($settings['irongate_firewall'] ?? 'true') === 'true' ? 'true' : 'false') . "\n\n";
    
    // Layer 8: Blockchain settings
    // irongate-audit: migrated from Algorand to Midnight. The Midnight read path
    // is unauthenticated, so app_id and admin_mnemonic are gone entirely - the
    // mnemonic was previously persisted in the settings table, returned by an
    // unauthenticated API action, and written in plaintext into this
    // world-readable config file.
    $config .= "# Layer 8: Midnight Blockchain Verification\n";
    $config .= "blockchain:\n";
    $config .= "  enabled: " . (($settings['blockchain_enabled'] ?? 'false') === 'true' ? 'true' : 'false') . "\n";
    $network = $settings['blockchain_network'] ?? 'preprod';
    if (!in_array($network, ['preprod', 'preview', 'mainnet', 'undeployed'], true)) {
        $network = 'preprod';
    }
    $config .= "  network: " . yamlScalar($network) . "\n";
    $contract = $settings['blockchain_contract_address'] ?? '';
    if (!empty($contract) && $contract !== 'null') {
        $config .= "  contract_address: " . yamlScalar($contract) . "\n";
    } else {
        $config .= "  contract_address: null\n";
    }
    $indexer = $settings['blockchain_indexer_url'] ?? '';
    if (!empty($indexer) && $indexer !== 'null') {
        $config .= "  indexer_url: " . yamlScalar($indexer) . "\n";
    } else {
        $config .= "  indexer_url: null\n";
    }
    $config .= "  cache_ttl: " . intval($settings['blockchain_cache_ttl'] ?? 60) . "\n";
    $config .= "  fallback_allow: " . (($settings['blockchain_fallback_allow'] ?? 'true') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  audit_logging: " . (($settings['blockchain_audit_logging'] ?? 'false') === 'true' ? 'true' : 'false') . "\n";
    $config .= "  allow_rogue_devices: " . (($settings['blockchain_allow_rogue_devices'] ?? 'false') === 'true' ? 'true' : 'false') . "\n\n";
    
    // Get custom device groups from database
    $groupResults = $db->query('SELECT * FROM device_groups ORDER BY name');
    $customGroups = [];
    while ($row = $groupResults->fetchArray(SQLITE3_ASSOC)) {
        $customGroups[] = $row;
    }

    $config .= "# Custom Device Groups\n";
    $config .= "custom_groups:\n";
    if (!empty($customGroups)) {
        foreach ($customGroups as $group) {
            $config .= "  - name: " . yamlScalar($group['name']) . "\n";
            $config .= "    color: " . yamlScalar($group['color']) . "\n";
            $config .= "    icon: " . yamlScalar($group['icon']) . "\n";
            $config .= "    description: " . yamlScalar($group['description'] ?? '') . "\n";
            $config .= "    lan_access: " . yamlScalar($group['lan_access'] ?? 'none') . "\n";
            $canAccess = json_decode($group['can_access_groups'] ?? '[]', true) ?: [];
            $config .= "    can_access_groups: [" . implode(', ', array_map(function($g) { return yamlScalar($g); }, $canAccess)) . "]\n";
        }
    } else {
        $config .= "  []\n";
    }
    $config .= "\n";

    // Get protected devices from database
    $results = $db->query('SELECT mac, ip, zone FROM irongate_devices');
    $devices = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $devices[] = $row;
    }

    $config .= "devices:\n";
    if (!empty($devices)) {
        foreach ($devices as $dev) {
            $config .= "  - mac: " . yamlScalar($dev['mac']) . "\n";
            $config .= "    ip: " . yamlScalar($dev['ip']) . "\n";
            $config .= "    zone: " . yamlScalar($dev['zone']) . "\n";
        }
    } else {
        $config .= "  []\n";
    }

    // Write config
    @mkdir('/etc/irongate', 0775, true);
    $writeResult = @file_put_contents('/etc/irongate/config.yaml', $config);
    if ($writeResult === false) {
        // Try to fix permissions and retry
        @chmod('/etc/irongate', 0775);
        @chown('/etc/irongate', 'root');
        @chgrp('/etc/irongate', 'www-data');
        $writeResult = @file_put_contents('/etc/irongate/config.yaml', $config);
        if ($writeResult === false) {
            return [
                'success' => false,
                'error' => 'Failed to write config file - check /etc/irongate permissions'
            ];
        }
    }
    
    // Restart service in background - don't wait for it
    exec('sudo systemctl restart irongate >/dev/null 2>&1 &');
    
    return ['success' => true, 'message' => 'Irongate configuration applied', 'mode' => $mode];
}
