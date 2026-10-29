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
// irongate-audit (V3): no CORS headers. The dashboard (index.php) calls this API
// with a relative URL, so it is same-origin; a wildcard Access-Control-Allow-Origin
// only let any web page a LAN browser visited drive this API cross-origin.

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Session guard: all API actions require an authenticated WebUI session.
// Localhost calls without a session cookie are exempted inside the guard.
require_once __DIR__ . '/session_check.php';

$db = new SQLite3('/var/www/irongate/dhcp.db');
// irongate-audit: without a busy timeout, a concurrent php-fpm worker holding
// the write lock made this connection fail immediately, silently dropping
// setting writes and config regeneration under load.
$db->busyTimeout(5000);
$action = $_GET['action'] ?? '';

// CSRF gate (operator ruling): every action that changes the configuration, the credentials, the access list,
// the DHCP service or the update settings needs this session's X-CSRF-Token, on any method. The gate is skipped
// only by irongate_csrf_not_required() - the one cli-server + IRONGATE_TEST_SANDBOX=1 seam the PHP suites use.
// update_now keeps its own check below.
$IRONGATE_CSRF_ACTIONS = ['settings', 'irongate_settings', 'irongate_toggle', 'irongate_apply', 'device_groups',
                          'irongate_devices', 'change_password', 'change_username', 'update_access_list',
                          'toggle_access_list', 'apply', 'reservations', 'start', 'stop', 'restart', 'repair',
                          'validate', 'update_check', 'update_settings'];
// These five also serve a read-only GET; only their writes need the token. Every other listed action runs on any
// method (apply, validate, update_check, start, stop, restart, repair) and is gated unconditionally, GET included.
$IRONGATE_CSRF_READ_ACTIONS = ['settings', 'device_groups', 'irongate_devices', 'reservations',
                               'update_settings'];
if (in_array($action, $IRONGATE_CSRF_ACTIONS, true)
    && !($_SERVER['REQUEST_METHOD'] === 'GET' && in_array($action, $IRONGATE_CSRF_READ_ACTIONS, true))) {
    irongate_require_csrf();
}

// Helper functions
function getSetting($db, $key) {
    $stmt = $db->prepare('SELECT value FROM settings WHERE key = ?');
    $stmt->bindValue(1, $key, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    return $row ? $row['value'] : null;
}

function setSetting($db, $key, $value) {
    // irongate-audit (O3): backstop for every caller, whatever the endpoint checked before.
    if (is_string($key) && strpos($key, 'irongate_') === 0 && !validIrongateSetting($key, $value)) {
        return false;
    }
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

// Hand a request to the root helper (the only writer of config.yaml and auth.json). The verb is one of the
// three the installer's sudoers rule allows; the payload is JSON on stdin, never a path or an argument.
function irongateWriteViaHelper($verb, array $payload) {
    $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = @proc_open(['sudo', '-n', '/usr/local/sbin/irongate-webwrite', $verb], $spec, $pipes);
    if (!is_resource($proc)) {
        return ['success' => false, 'error' => 'helper unavailable'];
    }
    @fwrite($pipes[0], json_encode($payload));
    @fclose($pipes[0]);
    $out = (string)stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $rc = proc_close($proc);
    $body = json_decode(trim($out), true);
    if ($rc !== 0 || !is_array($body) || ($body['success'] ?? false) !== true) {
        return ['success' => false, 'error' => is_array($body) && is_string($body['error'] ?? null)
            ? $body['error'] : 'helper failed'];
    }
    return ['success' => true, 'changed' => (bool)($body['changed'] ?? false)];
}

// irongate-audit (V1): zone/group names and device IPs are interpolated into an
// nftables ruleset by the root engine, so only strict values may be stored.
// \z (not $) so a trailing newline cannot slip through. The name becomes the nft
// set identifier "<name>_devices", which cannot start with a digit or '-'.
function validZoneName($name) {
    return is_string($name) && preg_match('/^[A-Za-z_][A-Za-z0-9_-]{0,31}\z/', $name) === 1;
}

function validDeviceIp($ip) {
    return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

// irongate-audit (O3): the irongate_* settings are copied into /etc/irongate/config.yaml, which the root
// engine reads and, in dual-NIC mode, turns into bridge, nft and dnsmasq commands. yamlScalar() keeps a
// value from breaking the YAML but not from being a hostile string, so every key has a fixed shape here
// and an unknown irongate_* key is refused. Interface names follow the kernel's rules (1-15 characters,
// not starting with '-' or '.'); the addresses are IPv4 literals; the empty string means "not set".
// \z (not $) so a trailing newline cannot slip through.
function validIrongateSetting($key, $value) {
    static $flags = ['irongate_enabled', 'irongate_arp_defense', 'irongate_ipv6_ra', 'irongate_gateway_takeover',
                     'irongate_bypass_detection', 'irongate_firewall'];
    static $addrs = ['irongate_bridge_ip', 'irongate_bridge_dhcp_start', 'irongate_bridge_dhcp_end'];
    if (!is_string($key) || !is_string($value)) return false;
    if (in_array($key, $flags, true)) return $value === 'true' || $value === 'false';
    if ($key === 'irongate_mode') return $value === 'single' || $value === 'dual';
    if ($key === 'irongate_isolated_interface') {
        return $value === '' || preg_match('/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}\z/', $value) === 1;
    }
    if (in_array($key, $addrs, true)) {
        return $value === '' || filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }
    return false;
}

// The first problem in the irongate_* entries of a settings POST, or null. Checked before anything is stored.
function irongateSettingsError($data) {
    if (!is_array($data)) return null;
    foreach ($data as $key => $value) {
        if (is_string($key) && strpos($key, 'irongate_') === 0 && !validIrongateSetting($key, $value)) {
            return 'Invalid value or unknown setting: ' . preg_replace('/[^\x20-\x7e]/', '?', substr($key, 0, 40));
        }
    }
    return null;
}

function cidrToHosts($cidr) {
    return pow(2, 32 - intval($cidr)) - 2;
}

// Validate an allow-list entry: single IP (v4/v6) or IPv4 CIDR. Returns the
// trimmed entry on success, false otherwise. Used by the auth endpoints.
function validAllowEntry($v) {
    $v = trim((string)$v);
    if (filter_var($v, FILTER_VALIDATE_IP)) return $v;
    if (preg_match('#^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$#', $v, $m)) {
        for ($i = 1; $i <= 4; $i++) { if (intval($m[$i]) > 255) return false; }
        if (intval($m[5]) > 32) return false;
        return $v;
    }
    return false;
}

// True when $ip is covered by one of the allow-list entries (exact or CIDR).
function aclCovers($entries, $ip) {
    foreach ($entries as $e) {
        if ($e === $ip) return true;
        if (strpos($e, '/') !== false) {
            list($net, $bits) = explode('/', $e, 2);
            $ipL = ip2long($ip);
            $netL = ip2long($net);
            $bits = intval($bits);
            if ($ipL !== false && $netL !== false && $bits >= 0 && $bits <= 32) {
                $mask = $bits === 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;
                if (($ipL & $mask) === ($netL & $mask)) return true;
            }
        }
    }
    return false;
}

// Midnight indexer presets — mirror of blockchain.py NETWORKS (Layer 8).
function midnightNetworks() {
    return [
        'preprod'    => 'https://indexer.preprod.midnight.network/api/v4/graphql',
        'preview'    => 'https://indexer.preview.midnight.network/api/v4/graphql',
        'mainnet'    => 'https://indexer.mainnet.midnight.network/api/v4/graphql',
        'undeployed' => 'http://127.0.0.1:8088/api/v4/graphql',
    ];
}

// irongate-audit (V2, SSRF): a custom indexer URL must be https and its host
// must be the host of one of the https presets above (same rule as
// blockchain.py). Otherwise the probe below could be aimed at loopback, LAN or
// cloud-metadata addresses from the web tier.
// (FILTER_VALIDATE_URL is intentionally not used: it accepts exactly the
// printable-ASCII set that the first check below already enforces.)
function validIndexerUrl($url) {
    if (!is_string($url) || !preg_match('/^[\x21-\x7e]+\z/', $url) || strpos($url, '\\') !== false) {
        return false;
    }
    $p = parse_url($url);
    // Exactly "https", no case folding: parse_url() keeps the case and PHP's stream layer does not
    // fold it either (PHP 8.3 sends the request for an all-upper-case "HTTPS://" in cleartext).
    if ($p === false || ($p['scheme'] ?? '') !== 'https') return false;
    if (isset($p['user']) || isset($p['pass'])) return false;
    if (isset($p['port']) && $p['port'] !== 443) return false;
    $hosts = [];
    foreach (midnightNetworks() as $preset) {
        $pp = parse_url($preset);
        if (strtolower($pp['scheme'] ?? '') === 'https' && !empty($pp['host'])) {
            $hosts[] = strtolower($pp['host']);
        }
    }
    return in_array(strtolower($p['host'] ?? ''), $hosts, true);
}

// Resolve the effective indexer endpoint: custom URL (https, known Midnight
// indexer host only) overrides the network preset, matching blockchain.py.
function midnightEndpoint($network, $custom) {
    $custom = trim((string)$custom);
    if ($custom !== '') {
        // The selected network's own preset (e.g. the local 'undeployed' node) is always fine.
        if ($custom !== (midnightNetworks()[$network] ?? null) && !validIndexerUrl($custom)) {
            return null;
        }
        return $custom;
    }
    $nets = midnightNetworks();
    return $nets[$network] ?? null;
}

// Probe a Midnight indexer with a minimal GraphQL query. Pure PHP streams —
// no shell involved. Returns reachable/response_time_ms/http_code/error.
function midnightProbe($endpoint, $timeout) {
    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\nUser-Agent: Irongate-WebUI\r\n",
            'content' => '{"query":"{__typename}"}',
            'timeout' => $timeout,
            'ignore_errors' => true,
            // irongate-audit (V2): never follow a redirect. An allowed host must not be
            // able to bounce the probe to loopback, the LAN or cloud metadata.
            'follow_location' => 0,
            'max_redirects' => 0,
        ],
    ]);
    $t0 = microtime(true);
    $body = @file_get_contents($endpoint, false, $ctx);
    $ms = (int)round((microtime(true) - $t0) * 1000);
    $code = 0;
    if (isset($http_response_header[0]) && preg_match('#HTTP/\S+\s+(\d{3})#', $http_response_header[0], $m)) {
        $code = intval($m[1]);
    }
    if ($body === false && $code === 0) {
        return ['reachable' => false, 'response_time_ms' => $ms, 'http_code' => 0,
                'error' => $ms >= ($timeout * 1000 - 100) ? 'connection timeout' : 'connection failed'];
    }
    // A 3xx is not an answer: redirects are not followed (see above).
    $ok = $code >= 200 && $code < 300;
    return ['reachable' => $ok, 'response_time_ms' => $ms, 'http_code' => $code,
            'error' => $ok ? null : 'indexer returned HTTP ' . $code];
}

// Write the access-control JSON and regenerate the nginx snippet via sudo.
// Returns ['success'=>bool, 'error'=>?, 'detail'=>?].
function writeAclAndRegen($acl) {
    $acl['updated_at'] = date('c');
    if (@file_put_contents('/etc/irongate/access-control.json',
            json_encode($acl, JSON_PRETTY_PRINT) . "\n", LOCK_EX) === false) {
        return ['success' => false, 'error' => 'Failed to write access-control config'];
    }
    exec('sudo /opt/irongate/regen-access.sh 2>&1', $regenOut, $regenCode);
    if ($regenCode !== 0) {
        return ['success' => false, 'error' => 'nginx regeneration failed',
                'detail' => implode("\n", array_slice($regenOut, -5))];
    }
    return ['success' => true, 'acl' => $acl];
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
        return true;
    }
    return false;
}

function deleteReservation($db, $id) {
    $stmt = $db->prepare('DELETE FROM reservations WHERE id = ?');
    $stmt->bindValue(1, $id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    return $result ? true : false;
}

// irongate-audit (O4): the web tier no longer writes /etc/dnsmasq.conf or anything in /etc/dnsmasq.d. dnsmasq runs
// as root and a `dhcp-script=` line in either would run a program as root, so both belong to root. This API stores
// the settings and reservations in the database as before; to apply them it stages them as DATA in
// DNSMASQ_STAGE_DIR (a root-owned directory outside the web root) and runs the one root helper below through sudo
// with no arguments (/etc/sudoers.d/irongate-dnsmasq-apply). The helper accepts only the keys listed here, checks
// each value, renders the files from its own template, runs `dnsmasq --test` and restarts dnsmasq.
const DNSMASQ_HELPER = '/opt/irongate/dnsmasq-apply';
const DNSMASQ_STAGE_DIR = '/var/lib/irongate/dnsmasq-staged';
const DNSMASQ_SETTING_KEYS = ['dhcp_enabled', 'interface', 'cidr', 'range_start', 'range_end', 'gateway',
                              'dns_primary', 'dns_secondary', 'lease_time', 'domain'];

function dnsmasqRequest($db, $action) {
    $all = getAllSettings($db);
    $settings = [];
    foreach (DNSMASQ_SETTING_KEYS as $key) {
        if (isset($all[$key]) && is_scalar($all[$key])) {
            // The old generator wrote the values as they were and dnsmasq ignores white space around them, so a gateway
            // saved with a trailing space worked. The helper strips as well; a value that is not plain is refused there.
            $settings[$key] = trim((string)$all[$key]);
        }
    }
    // As before: the DHCP options count only while DHCP is on and a range is set, and an empty interface means
    // "the default route's" (the helper looks that up).
    $on = ($settings['dhcp_enabled'] ?? '') === 'true' && !empty($settings['range_start'] ?? '') && !empty($settings['range_end'] ?? '');
    if (!$on) {
        $settings = array_intersect_key($settings, ['interface' => 1]);
    }
    $settings['dhcp_enabled'] = $on ? 'true' : 'false';
    if (empty($settings['interface'] ?? '')) {
        unset($settings['interface']);
    }
    $reservations = [];
    $results = $db->query('SELECT * FROM reservations');
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $reservations[] = [
            'mac' => trim((string)$row['mac']),
            'ip' => trim((string)$row['ip']),
            'hostname' => sanitizeHostname((string)($row['hostname'] ?? '')),
        ];
    }
    return ['version' => 1, 'action' => $action, 'settings' => (object)$settings, 'reservations' => $reservations];
}

// Stage the request and run the helper. Returns ['ok' => bool, 'error' => string, 'resp' => array|null].
function runDnsmasqHelper($db, $action) {
    $json = json_encode(dnsmasqRequest($db, $action));
    if ($json === false) {
        return ['ok' => false, 'error' => 'the request could not be encoded', 'resp' => null];
    }
    $dir = DNSMASQ_STAGE_DIR;
    $lock = @fopen($dir . '/.lock', 'c');
    if ($lock === false) {
        return ['ok' => false, 'error' => 'the staging directory is not writable', 'resp' => null];
    }
    flock($lock, LOCK_EX);
    // A directory named request.json would make every rename below fail for good; an empty one is ours to remove.
    if (is_dir($dir . '/request.json') && !is_link($dir . '/request.json')) {
        @rmdir($dir . '/request.json');
    }
    $tmp = @tempnam($dir, '.req-');
    if ($tmp === false || @file_put_contents($tmp, $json) === false || !@rename($tmp, $dir . '/request.json')) {
        if ($tmp !== false) {
            @unlink($tmp);
        }
        flock($lock, LOCK_UN);
        fclose($lock);
        return ['ok' => false, 'error' => 'the request could not be staged', 'resp' => null];
    }
    $out = [];
    exec('sudo -n ' . DNSMASQ_HELPER . ' 2>&1', $out, $rc);
    flock($lock, LOCK_UN);
    fclose($lock);
    $resp = null;
    foreach (array_reverse($out) as $line) {
        $decoded = json_decode($line, true);
        if (is_array($decoded) && array_key_exists('success', $decoded)) {
            $resp = $decoded;
            break;
        }
    }
    if ($resp === null) {
        return ['ok' => false, 'error' => 'dnsmasq-apply gave no answer: ' . substr(implode(' ', $out), 0, 300), 'resp' => null];
    }
    return ['ok' => true, 'error' => '', 'resp' => $resp];
}

// Validate dnsmasq config before applying (what the settings in the database would render to)
function validateConfig($db) {
    $run = runDnsmasqHelper($db, 'validate');
    $resp = $run['resp'];
    if (!$run['ok']) {
        return ['valid' => false, 'output' => $run['error'], 'return_code' => 1];
    }
    if (!($resp['success'] ?? false)) {
        return ['valid' => false, 'output' => (string)($resp['error'] ?? ''), 'return_code' => 2];
    }
    return [
        'valid' => (bool)($resp['valid'] ?? false),
        'output' => (string)($resp['output'] ?? ''),
        'return_code' => (int)($resp['return_code'] ?? 1)
    ];
}

function applyConfig($db) {
    $run = runDnsmasqHelper($db, 'apply');
    if (!$run['ok']) {
        return [
            'success' => false,
            'error' => 'Config validation failed: ' . $run['error'],
            'stage' => 'validation'
        ];
    }
    $resp = $run['resp'];
    if ($resp['success'] ?? false) {
        return ['success' => true];
    }
    if (($resp['stage'] ?? '') === 'start') {
        // Get the actual error from journalctl
        exec('journalctl -u dnsmasq -n 20 --no-pager 2>&1', $journalOutput);
        return [
            'success' => false,
            'error' => 'Service start failed',
            'output' => (string)($resp['output'] ?? ''),
            'journal' => implode("\n", $journalOutput),
            'stage' => 'start'
        ];
    }
    return [
        'success' => false,
        'error' => 'Config validation failed: ' . (string)($resp['error'] ?? ''),
        'stage' => 'validation'
    ];
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
            // This endpoint stores any key, the irongate_* ones included: same rules as irongate_settings.
            $settingsError = irongateSettingsError($data);
            if ($settingsError !== null) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => $settingsError]);
                break;
            }

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
        $result = validateConfig($db);
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
            $settingsError = irongateSettingsError($data);
            if ($settingsError !== null) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => $settingsError]);
                break;
            }
            // Layer 8 validation: never persist an enable without a contract
            // address, an unknown network, or a malformed indexer URL.
            if (is_array($data) && (array_key_exists('blockchain_enabled', $data)
                || array_key_exists('blockchain_network', $data)
                || array_key_exists('blockchain_indexer_url', $data))) {
                $reqEnabled = ($data['blockchain_enabled'] ?? (getSetting($db, 'blockchain_enabled') ?? 'false')) === 'true';
                $reqContract = trim((string)($data['blockchain_contract_address']
                    ?? (getSetting($db, 'blockchain_contract_address') ?? '')));
                if ($reqEnabled && $reqContract === '') {
                    echo json_encode(['success' => false, 'error' => 'Layer 8 cannot be enabled without a contract address']);
                    break;
                }
                if (array_key_exists('blockchain_network', $data)
                    && !array_key_exists((string)$data['blockchain_network'], midnightNetworks())) {
                    echo json_encode(['success' => false, 'error' => 'Unknown blockchain network']);
                    break;
                }
                $reqIndexer = trim((string)($data['blockchain_indexer_url'] ?? ''));
                $reqNetwork = (string)($data['blockchain_network'] ?? (getSetting($db, 'blockchain_network') ?? 'preprod'));
                if ($reqIndexer !== '' && $reqIndexer !== (midnightNetworks()[$reqNetwork] ?? null)
                    && !validIndexerUrl($reqIndexer)) {
                    http_response_code(400);
                    echo json_encode(['success' => false, 'error' => 'Invalid indexer URL (must be https on a known Midnight indexer host)']);
                    break;
                }
                // Store exactly what was validated (trimmed), not the raw value: the engine refuses a
                // URL with surrounding whitespace, so storing the padded text would silently switch Layer 8 off.
                if (array_key_exists('blockchain_indexer_url', $data)) {
                    $data['blockchain_indexer_url'] = $reqIndexer;
                }
            }
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

            // irongate-audit (V1): group names (and the names a group may reach)
            // become nft set identifiers in the root engine.
            $accessList = $data['can_access_groups'] ?? [];
            $accessOk = is_array($accessList);
            foreach (($accessOk ? $accessList : []) as $g) {
                if (!validZoneName($g)) { $accessOk = false; }
            }
            if (!validZoneName($name) || !$accessOk) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Invalid group name (letters, digits, _ and -, starting with a letter or _, max 32 characters)']);
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
            // irongate-audit (V1): ip and zone end up inside the root engine's nft
            // ruleset. An empty ip is still allowed (the engine skips such devices).
            $devIp = $data['ip'] ?? '';
            $devZone = $data['zone'] ?? 'isolated';
            if (($devIp !== '' && !validDeviceIp($devIp)) || !validZoneName($devZone)) {
                http_response_code(400);
                echo json_encode(['success' => false, 'error' => 'Invalid ip (IPv4 address) or zone (letters, digits, _ and -, starting with a letter or _, max 32 characters)']);
                break;
            }
            $stmt = $db->prepare('INSERT OR REPLACE INTO irongate_devices (mac, ip, hostname, zone) VALUES (?, ?, ?, ?)');
            $stmt->bindValue(1, strtolower($data['mac']), SQLITE3_TEXT);
            $stmt->bindValue(2, $devIp, SQLITE3_TEXT);
            $stmt->bindValue(3, $data['hostname'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(4, $devZone, SQLITE3_TEXT);
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
        // This starts a root process. It needs an authenticated session of its own - the localhost bypass of the
        // session guard (cli-server only) never applies to it - and the CSRF token of that session in the
        // X-CSRF-Token header (compared in constant time); a cross-site POST carries the cookie but not the token.
        if (($_SESSION['authenticated'] ?? false) !== true) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'auth_required']);
            break;
        }
        $csrfSent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        $csrfWant = $_SESSION['csrf_token'] ?? '';
        if (!is_string($csrfSent) || !is_string($csrfWant) || $csrfWant === '' || !hash_equals($csrfWant, $csrfSent)) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'invalid csrf token']);
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
        
        // irongate-audit (D5/D6): this used to download the installer as www-data
        // into a world-writable path and sudo-execute it. Any local user could
        // replace that file first, so an unauthenticated request became root code
        // execution. The web tier now only TRIGGERS the update; the root-owned
        // updater fetches the installer, pins it to a commit, and verifies it
        // before running. No attacker-supplied bytes are ever executed from here.
        exec("sudo touch /var/log/irongate-update.log");
        exec("sudo chown www-data /var/log/irongate-update.log");
        // The update runs as its own systemd unit (own cgroup: it is not a child of php-fpm, which the installer
        // restarts); the only thing sudo allows www-data to run for it is exactly this command.
        $out = [];
        $rc = 1;
        exec("sudo -n /usr/bin/systemctl start --no-block irongate-updater-now.service", $out, $rc);
        if ($rc !== 0) {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Could not start the update service']);
            break;
        }
        
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
    
    // --- Layer 8 Midnight endpoints (session-protected) ---
    case 'test_blockchain_connection':
        $data = json_decode(file_get_contents('php://input'), true) ?: [];
        $settings = getAllSettings($db);
        $network = (string)($data['network'] ?? ($settings['blockchain_network'] ?? 'preprod'));
        $custom = (string)($data['indexer_url'] ?? ($settings['blockchain_indexer_url'] ?? ''));
        if (!array_key_exists($network, midnightNetworks())) {
            echo json_encode(['success' => false, 'error' => 'Unknown network; expected one of: '
                . implode(', ', array_keys(midnightNetworks()))]);
            break;
        }
        $endpoint = midnightEndpoint($network, $custom);
        if ($endpoint === null) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid indexer URL (must be https on a known Midnight indexer host)']);
            break;
        }
        $probe = midnightProbe($endpoint, 5);
        echo json_encode([
            'success' => true,
            'endpoint' => $endpoint,
            'reachable' => $probe['reachable'],
            'response_time_ms' => $probe['response_time_ms'],
            'http_code' => $probe['http_code'],
            'error' => $probe['error'],
        ]);
        break;

    case 'get_blockchain_status':
        $settings = getAllSettings($db);
        $enabled = ($settings['blockchain_enabled'] ?? 'false') === 'true';
        $contract = trim((string)($settings['blockchain_contract_address'] ?? ''));
        $network = $settings['blockchain_network'] ?? 'preprod';
        $endpoint = midnightEndpoint($network, $settings['blockchain_indexer_url'] ?? '');
        $engineActive = trim((string)shell_exec('systemctl is-active irongate 2>/dev/null')) === 'active';
        $probe = null;
        if ($contract !== '' && $endpoint !== null) {
            $probe = midnightProbe($endpoint, 3);
        }
        if ($contract === '') {
            $state = 'not_configured';
        } elseif (!$enabled) {
            $state = 'disabled';
        } elseif ($probe !== null && $probe['reachable']) {
            $state = 'active';
        } else {
            $state = 'degraded';
        }
        $journal = [];
        exec('sudo /usr/bin/journalctl -u irongate -n 80 --no-pager 2>/dev/null', $jout);
        foreach ($jout as $line) {
            if (stripos($line, 'blockchain') !== false || stripos($line, 'Layer 8') !== false) {
                $journal[] = $line;
            }
        }
        echo json_encode(['success' => true, 'data' => [
            'state' => $state,
            'enabled' => $enabled,
            'network' => $network,
            'contract_address' => $contract,
            'endpoint' => $endpoint,
            'engine_active' => $engineActive,
            'indexer_reachable' => $probe !== null ? $probe['reachable'] : null,
            'response_time_ms' => $probe !== null ? $probe['response_time_ms'] : null,
            'recent_log' => array_slice($journal, -5),
        ]]);
        break;

    // --- Auth management endpoints (added by webauth feature; session-protected) ---
    case 'change_password':
        $data = json_decode(file_get_contents('php://input'), true);
        $cur = (string)($data['current_password'] ?? '');
        $new = (string)($data['new_password'] ?? '');
        $confirm = (string)($data['confirm_password'] ?? '');
        $auth = json_decode(@file_get_contents('/etc/irongate/auth.json'), true);
        if (!is_array($auth) || empty($auth['password_hash'])) {
            echo json_encode(['success' => false, 'error' => 'Auth config unavailable']);
            break;
        }
        if (!password_verify($cur, $auth['password_hash'])) {
            echo json_encode(['success' => false, 'error' => 'Current password is incorrect']);
            break;
        }
        if (strlen($new) < 8) {
            echo json_encode(['success' => false, 'error' => 'New password must be at least 8 characters']);
            break;
        }
        if ($new !== $confirm) {
            echo json_encode(['success' => false, 'error' => 'New passwords do not match']);
            break;
        }
        if (irongate_test_sandbox()) {
            // PHP suites (built-in server + IRONGATE_TEST_SANDBOX=1): the old direct write. Dead under php-fpm.
            $auth['password_hash'] = password_hash($new, PASSWORD_BCRYPT);
            $auth['updated_at'] = date('c');
            if (@file_put_contents('/etc/irongate/auth.json',
                    json_encode($auth, JSON_PRETTY_PRINT) . "\n", LOCK_EX) === false) {
                echo json_encode(['success' => false, 'error' => 'Failed to write auth config']);
                break;
            }
        } else {
            // Only the new hash reaches the root helper; the plaintext never leaves this process.
            $result = irongateWriteViaHelper('auth-set-credentials',
                ['password_hash' => password_hash($new, PASSWORD_BCRYPT)]);
            if (!$result['success']) {
                echo json_encode(['success' => false, 'error' => 'Failed to write auth config']);
                break;
            }
        }
        echo json_encode(['success' => true, 'message' => 'Password changed']);
        break;

    case 'change_username':
        $data = json_decode(file_get_contents('php://input'), true);
        $cur = (string)($data['current_password'] ?? '');
        $newUser = trim((string)($data['new_username'] ?? ''));
        $auth = json_decode(@file_get_contents('/etc/irongate/auth.json'), true);
        if (!is_array($auth) || empty($auth['password_hash'])) {
            echo json_encode(['success' => false, 'error' => 'Auth config unavailable']);
            break;
        }
        if (!password_verify($cur, $auth['password_hash'])) {
            echo json_encode(['success' => false, 'error' => 'Current password is incorrect']);
            break;
        }
        if (!preg_match('/^[A-Za-z0-9_.-]{1,32}$/', $newUser)) {
            echo json_encode(['success' => false, 'error' => 'Username must be 1-32 characters: letters, digits, dot, dash, underscore']);
            break;
        }
        if (irongate_test_sandbox()) {
            // PHP suites (built-in server + IRONGATE_TEST_SANDBOX=1): the old direct write. Dead under php-fpm.
            $auth['username'] = $newUser;
            $auth['updated_at'] = date('c');
            if (@file_put_contents('/etc/irongate/auth.json',
                    json_encode($auth, JSON_PRETTY_PRINT) . "\n", LOCK_EX) === false) {
                echo json_encode(['success' => false, 'error' => 'Failed to write auth config']);
                break;
            }
        } else {
            $result = irongateWriteViaHelper('auth-set-username', ['username' => $newUser]);
            if (!$result['success']) {
                echo json_encode(['success' => false, 'error' => 'Failed to write auth config']);
                break;
            }
        }
        $_SESSION['username'] = $newUser;
        echo json_encode(['success' => true, 'message' => 'Username changed']);
        break;

    case 'get_access_list':
        $acl = json_decode(@file_get_contents('/etc/irongate/access-control.json'), true);
        if (!is_array($acl)) {
            $acl = ['enabled' => false, 'allowed_ips' => []];
        }
        echo json_encode(['success' => true, 'data' => $acl]);
        break;

    case 'update_access_list':
        $data = json_decode(file_get_contents('php://input'), true);
        if (!is_array($data) || !isset($data['allowed_ips']) || !is_array($data['allowed_ips'])) {
            echo json_encode(['success' => false, 'error' => 'Invalid request body']);
            break;
        }
        $ips = [];
        $bad = null;
        foreach ($data['allowed_ips'] as $entry) {
            $valid = validAllowEntry($entry);
            if ($valid === false) { $bad = (string)$entry; break; }
            if (!in_array($valid, $ips, true)) $ips[] = $valid;
        }
        if ($bad !== null) {
            echo json_encode(['success' => false, 'error' => 'Invalid IP or CIDR: ' . $bad]);
            break;
        }
        if (!in_array('127.0.0.1', $ips, true)) {
            array_unshift($ips, '127.0.0.1'); // never lock out localhost
        }
        $result = writeAclAndRegen([
            'enabled' => (bool)($data['enabled'] ?? true),
            'allowed_ips' => $ips
        ]);
        if (!$result['success']) {
            echo json_encode($result);
            break;
        }
        $warning = null;
        $remote = $_SERVER['REMOTE_ADDR'] ?? '';
        if ($result['acl']['enabled'] && $remote !== ''
            && !in_array($remote, ['127.0.0.1', '::1'], true)
            && !aclCovers($ips, $remote)) {
            $warning = 'Your current IP (' . $remote . ') is not in the allow-list. You may lose access.';
        }
        echo json_encode(['success' => true, 'message' => 'Access list updated',
                          'data' => $result['acl'], 'warning' => $warning]);
        break;

    case 'toggle_access_list':
        $data = json_decode(file_get_contents('php://input'), true);
        $acl = json_decode(@file_get_contents('/etc/irongate/access-control.json'), true);
        if (!is_array($acl) || !isset($acl['allowed_ips']) || !is_array($acl['allowed_ips'])) {
            $acl = ['allowed_ips' => ['127.0.0.1']];
        }
        $acl['enabled'] = (bool)($data['enabled'] ?? false);
        $result = writeAclAndRegen($acl);
        if (!$result['success']) {
            echo json_encode($result);
            break;
        }
        echo json_encode(['success' => true, 'data' => $result['acl']]);
        break;

    default:
        echo json_encode(['error' => 'Unknown action', 'available' => [
            'system', 'status', 'settings', 'apply', 'leases',
            'reservations', 'logs', 'restart', 'stop', 'start',
            'diagnostics', 'repair', 'validate',
            'irongate_status', 'irongate_settings', 'irongate_interfaces',
            'irongate_toggle', 'irongate_apply', 'irongate_logs', 'irongate_devices', 'device_groups',
            'update_check', 'update_settings', 'update_now', 'update_log',
            'change_password', 'change_username', 'get_access_list',
            'update_access_list', 'toggle_access_list',
            'test_blockchain_connection', 'get_blockchain_status'
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
    
    // The same values, as data, for the root helper (it validates and renders them; the web tier never
    // supplies YAML text). irongateWriteViaHelper() runs only outside the PHP-suites' cli-server seam.
    $groupResults = $db->query('SELECT * FROM device_groups ORDER BY name');
    $customGroups = [];
    while ($row = $groupResults->fetchArray(SQLITE3_ASSOC)) {
        $customGroups[] = $row;
    }
    $results = $db->query('SELECT mac, ip, zone FROM irongate_devices');
    $devices = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $devices[] = $row;
    }

    $blockchainNetwork = $settings['blockchain_network'] ?? 'preprod';
    if (!in_array($blockchainNetwork, ['preprod', 'preview', 'mainnet', 'undeployed'], true)) {
        $blockchainNetwork = 'preprod';
    }
    $contract = $settings['blockchain_contract_address'] ?? '';
    $contract = (!empty($contract) && $contract !== 'null') ? $contract : null;
    $indexer = $settings['blockchain_indexer_url'] ?? '';
    $indexer = (!empty($indexer) && $indexer !== 'null') ? $indexer : null;

    $payload = ['settings' => [
        'network' => [
            'interface' => $interface,
            'local_ip' => $localIp,
            'local_mac' => $localMac,
            'gateway_ip' => $gateway,
            'gateway_mac' => $gatewayMac,
        ],
        'mode' => $mode,
        'layers' => [
            'arp_defense' => (($settings['irongate_arp_defense'] ?? 'true') === 'true'),
            'ipv6_ra' => (($settings['irongate_ipv6_ra'] ?? 'true') === 'true'),
            'gateway_takeover' => (($settings['irongate_gateway_takeover'] ?? 'true') === 'true'),
            'bypass_detection' => (($settings['irongate_bypass_detection'] ?? 'true') === 'true'),
            'firewall' => (($settings['irongate_firewall'] ?? 'true') === 'true'),
        ],
        'blockchain' => [
            'enabled' => (($settings['blockchain_enabled'] ?? 'false') === 'true'),
            'network' => $blockchainNetwork,
            'contract_address' => $contract,
            'indexer_url' => $indexer,
            'cache_ttl' => intval($settings['blockchain_cache_ttl'] ?? 60),
            'fallback_allow' => (($settings['blockchain_fallback_allow'] ?? 'true') === 'true'),
            'audit_logging' => (($settings['blockchain_audit_logging'] ?? 'false') === 'true'),
            'allow_rogue_devices' => (($settings['blockchain_allow_rogue_devices'] ?? 'false') === 'true'),
        ],
        'custom_groups' => array_map(function($group) {
            return [
                'name' => (string)$group['name'],
                'color' => (string)($group['color'] ?? ''),
                'icon' => (string)($group['icon'] ?? ''),
                'description' => (string)($group['description'] ?? ''),
                'lan_access' => (string)($group['lan_access'] ?? 'none'),
                'can_access_groups' => json_decode($group['can_access_groups'] ?? '[]', true) ?: [],
            ];
        }, $customGroups),
        'devices' => array_map(function($dev) {
            return [
                'mac' => (string)$dev['mac'],
                'ip' => (string)($dev['ip'] ?? ''),
                'zone' => (string)($dev['zone'] ?? ''),
            ];
        }, $devices),
    ]];
    if ($mode === 'dual') {
        $payload['settings']['bridge'] = [
            'enabled' => true,
            'isolated_interface' => (string)($settings['irongate_isolated_interface'] ?? ''),
            'bridge_name' => 'br-irongate',
            'bridge_ip' => (string)($settings['irongate_bridge_ip'] ?? '10.99.0.1'),
            'bridge_netmask' => '255.255.0.0',
            'dhcp_start' => (string)($settings['irongate_bridge_dhcp_start'] ?? '10.99.1.1'),
            'dhcp_end' => (string)($settings['irongate_bridge_dhcp_end'] ?? '10.99.255.254'),
            'port_isolation' => true,
        ];
    }

    if (irongate_test_sandbox()) {
    // The PHP suites drive api.php under the built-in server (IRONGATE_TEST_SANDBOX=1): keep their old
    // direct write so they stay green. Dead under php-fpm - there the helper above is always used.
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

    // Write config. The directory is created 0750 only when absent and never chmodded/chowned afterwards:
    // outside this seam the installer creates it and the root helper does the writing.
    @mkdir('/etc/irongate', 0750, true);
    $writeResult = @file_put_contents('/etc/irongate/config.yaml', $config);
    if ($writeResult === false) {
        return [
            'success' => false,
            'error' => 'Failed to write config file - check /etc/irongate permissions'
        ];
    }

    return ['success' => true, 'message' => 'Irongate configuration applied', 'mode' => $mode];
    }

    // Root helper: it writes atomically and restarts irongate only when the bytes changed.
    $result = irongateWriteViaHelper('config-apply', $payload);
    if (!$result['success']) {
        return [
            'success' => false,
            'error' => 'Failed to write config file - check /etc/irongate permissions'
        ];
    }

    return ['success' => true, 'message' => 'Irongate configuration applied', 'mode' => $mode];
}
