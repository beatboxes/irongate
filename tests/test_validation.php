<?php
/**
 * Irongate web API validation tests (V1 nft injection input, V2 indexer SSRF, V3 CORS).
 *
 * Drives the real web/api.php end to end over HTTP (localhost caller) against a
 * scratch SQLite database, then checks the HTTP status, the JSON answer, the
 * response headers and what actually landed in the database.
 *
 * It overwrites /var/www/irongate and starts PHP's built-in web server on
 * 127.0.0.1:18099, so it refuses to run outside a throw-away sandbox. Use a
 * container with no network:
 *
 *   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w \
 *       php:8.3-cli php tests/test_validation.php web
 *
 * Exit status 0 = every case passed. Run it against the pre-fix web/ to see it fail.
 */

if (PHP_SAPI !== 'cli') { exit(1); }
if (getenv('IRONGATE_TEST_SANDBOX') !== '1') {
    fwrite(STDERR, "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container\n");
    exit(2);
}
$webDir = realpath($argv[1] ?? 'web');
$docroot = '/var/www/irongate';
if ($webDir === false || !is_file("$webDir/api.php")) { fwrite(STDERR, "usage: php test_validation.php <web-dir>\n"); exit(2); }
if (file_exists("$docroot/dhcp.db")) { fwrite(STDERR, "refusing to run: $docroot/dhcp.db already exists\n"); exit(2); }

@mkdir($docroot, 0777, true);
foreach (glob("$webDir/*.php") as $f) { copy($f, "$docroot/" . basename($f)); }

// Serve the copied web root with PHP's built-in web server so api.php sees a real
// SAPI: real request body, real status code, real response headers.
$port = 18099;
$server = proc_open(['php', '-S', "127.0.0.1:$port", '-t', $docroot],
    [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/tmp/irongate-test-server.log', 'w']], $sp);
register_shutdown_function(function () use ($server) { if (is_resource($server)) { proc_terminate($server); proc_close($server); } });
for ($i = 0; $i < 50; $i++) {
    $c = @fsockopen('127.0.0.1', $port, $en, $es, 0.2);
    if ($c) { fclose($c); break; }
    usleep(100000);
}
if (!$c) { fwrite(STDERR, "built-in server did not start\n"); exit(2); }

function makeDb($path) {
    @unlink($path);
    $db = new SQLite3($path);
    $db->exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE reservations (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE NOT NULL, ip TEXT NOT NULL, hostname TEXT, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE irongate_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE NOT NULL, ip TEXT, hostname TEXT, zone TEXT DEFAULT 'isolated', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE device_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, color TEXT DEFAULT '#6c757d', icon TEXT, description TEXT, lan_access TEXT DEFAULT 'none', can_access_groups TEXT DEFAULT '[]', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        INSERT INTO settings VALUES ('irongate_enabled','false'), ('blockchain_network','preprod');");
    $db->close();
    chmod($path, 0666);
}

function call($method, $action, $body = null) {
    global $port;
    $ctx = stream_context_create(['http' => [
        'method' => $method, 'ignore_errors' => true, 'timeout' => 30,
        'header' => "Content-Type: application/json\r\n",
        'content' => $body === null ? '' : json_encode($body)]]);
    $raw = (string)@file_get_contents("http://127.0.0.1:$port/api.php?action=" . urlencode($action), false, $ctx);
    $hdrs = $http_response_header ?? [];
    preg_match('#^HTTP/\S+\s+(\d{3})#', $hdrs[0] ?? '', $m);
    return ['status' => (int)($m[1] ?? 0), 'json' => json_decode($raw, true), 'raw' => $raw, 'headers' => $hdrs];
}

function dbx($sql) {
    global $docroot;
    $db = new SQLite3("$docroot/dhcp.db");
    $db->exec($sql);
    $db->close();
}

function dbq($sql) {
    global $docroot;
    $db = new SQLite3("$docroot/dhcp.db", SQLITE3_OPEN_READONLY);
    $r = $db->querySingle($sql);
    $db->close();
    return $r;
}

$pass = 0; $fail = 0;
function check($name, $cond, $detail = '') {
    global $pass, $fail;
    if ($cond) { $pass++; echo "PASS  $name\n"; }
    else { $fail++; echo "FAIL  $name" . ($detail !== '' ? "  -- $detail" : '') . "\n"; }
}
function brief($r) { return 'status=' . $r['status'] . ' body=' . substr(trim($r['raw']), 0, 200); }

makeDb("$docroot/dhcp.db");

// ---- V1: irongate_devices -------------------------------------------------
$dev = fn($mac, $ip, $zone) => ['mac' => $mac, 'ip' => $ip, 'hostname' => 'h', 'zone' => $zone];
$badDevices = [
    'ip nft injection'        => ['aa:00:00:00:00:01', '1.2.3.4 } ; flush ruleset ; {', 'isolated'],
    'zone nft injection'      => ['aa:00:00:00:00:02', '192.168.1.2', 'lan; drop'],
    'zone trailing newline'   => ['aa:00:00:00:00:03', '192.168.1.3', "lan\n"],
    'zone 33 chars'           => ['aa:00:00:00:00:04', '192.168.1.4', str_repeat('z', 33)],
    'ipv6 address'            => ['aa:00:00:00:00:05', '::1', 'isolated'],
    'ip trailing newline'     => ['aa:00:00:00:00:06', "192.168.1.6\n", 'isolated'],
    'ip as integer'           => ['aa:00:00:00:00:07', 5, 'isolated'],
    'ip as array'             => ['aa:00:00:00:00:08', ['1.2.3.4'], 'isolated'],
    'zone as array'           => ['aa:00:00:00:00:09', '192.168.1.9', ['x']],
    'empty zone'              => ['aa:00:00:00:00:0a', '192.168.1.10', ''],
];
foreach ($badDevices as $label => [$mac, $ip, $zone]) {
    $r = call('POST', 'irongate_devices', $dev($mac, $ip, $zone));
    $stored = dbq("SELECT COUNT(*) FROM irongate_devices WHERE mac = '$mac'");
    check("V1 devices: reject $label", $r['status'] === 400 && ($r['json']['success'] ?? null) === false && (int)$stored === 0, brief($r) . " rows=$stored");
}
$r = call('POST', 'irongate_devices', $dev('aa:00:00:00:00:20', '192.168.1.50', 'iot-cams_1'));
check('V1 devices: accept valid ip/zone (control)', $r['status'] === 200 && ($r['json']['success'] ?? null) === true
    && dbq("SELECT zone FROM irongate_devices WHERE mac='aa:00:00:00:00:20'") === 'iot-cams_1', brief($r));
$r = call('POST', 'irongate_devices', $dev('aa:00:00:00:00:21', '', 'isolated'));
check('V1 devices: accept empty ip (control, engine skips such devices)', ($r['json']['success'] ?? null) === true, brief($r));
$r = call('POST', 'irongate_devices', ['mac' => 'aa:00:00:00:00:22', 'ip' => '10.0.0.5']);
check('V1 devices: zone defaults to isolated (control)', ($r['json']['success'] ?? null) === true
    && dbq("SELECT zone FROM irongate_devices WHERE mac='aa:00:00:00:00:22'") === 'isolated', brief($r));

// ---- V1: device_groups ----------------------------------------------------
$r = call('POST', 'device_groups', ['name' => 'x; flush ruleset ; table inet evil {', 'lan_access' => 'full']);
check('V1 groups: reject nft-injection name', $r['status'] === 400 && (int)dbq("SELECT COUNT(*) FROM device_groups") === 0, brief($r));
// trim() strips a trailing newline before validation, so "cams\n" is stored as "cams":
// what matters is that no stored name ever carries a newline.
$r = call('POST', 'device_groups', ['name' => "cams\n", 'lan_access' => 'none']);
check('V1 groups: stored name never contains a newline', (int)dbq("SELECT COUNT(*) FROM device_groups WHERE name LIKE '%' || char(10) || '%'") === 0, brief($r));
$r = call('POST', 'device_groups', ['name' => "ca\nms", 'lan_access' => 'none']);
check('V1 groups: reject embedded-newline name', $r['status'] === 400, brief($r));
dbx('DELETE FROM device_groups');
$r = call('POST', 'device_groups', ['name' => 'cams', 'lan_access' => 'selected', 'can_access_groups' => ['a b']]);
check('V1 groups: reject injected can_access_groups entry', $r['status'] === 400 && (int)dbq("SELECT COUNT(*) FROM device_groups") === 0, brief($r));
$r = call('POST', 'device_groups', ['name' => 'cams', 'lan_access' => 'selected', 'can_access_groups' => 'servers']);
check('V1 groups: reject non-array can_access_groups', $r['status'] === 400 && (int)dbq("SELECT COUNT(*) FROM device_groups") === 0, brief($r));
$r = call('POST', 'device_groups', ['name' => 'servers', 'lan_access' => 'none']);
check('V1 groups: reserved name still refused (control, unchanged message)', ($r['json']['success'] ?? null) === false
    && stripos($r['raw'], 'reserved') !== false, brief($r));
$r = call('POST', 'device_groups', ['name' => 'cams', 'lan_access' => 'selected', 'can_access_groups' => ['servers', 'iot-cams_1']]);
check('V1 groups: accept valid group (control)', ($r['json']['success'] ?? null) === true
    && (int)dbq("SELECT COUNT(*) FROM device_groups WHERE name='cams'") === 1, brief($r));

// ---- V2: indexer URL ------------------------------------------------------
$badIndexers = [
    'cloud metadata over http' => 'http://169.254.169.254/latest/meta-data/',
    'file scheme'              => 'file:///etc/shadow',
    'loopback http'            => 'http://127.0.0.1:8088/api/v4/graphql',
    'unknown https host'       => 'https://evil.example/',
    'https loopback'           => 'https://127.0.0.1/',
    'host suffix trick'        => 'https://indexer.preprod.midnight.network.evil.example/',
    'userinfo trick'           => 'https://indexer.preprod.midnight.network@evil.example/',
    'backslash trick'          => 'https://evil.example\\@indexer.preprod.midnight.network/',
    'known host plain http'    => 'http://indexer.preprod.midnight.network/api/v4/graphql',
    'known host odd port'      => 'https://indexer.preprod.midnight.network:8443/api/v4/graphql',
];
foreach ($badIndexers as $label => $url) {
    $r = call('POST', 'irongate_settings', ['blockchain_network' => 'preprod', 'blockchain_indexer_url' => $url]);
    $saved = dbq("SELECT value FROM settings WHERE key='blockchain_indexer_url'");
    check("V2 save: reject $label", $r['status'] === 400 && ($r['json']['success'] ?? null) === false && $saved === null, brief($r) . " saved=" . var_export($saved, true));
    $r = call('POST', 'test_blockchain_connection', ['network' => 'preprod', 'indexer_url' => $url]);
    check("V2 probe: refuse to contact $label", $r['status'] === 400 && !isset($r['json']['endpoint']), brief($r));
}
$good = 'https://indexer.mainnet.midnight.network/api/v4/graphql';
$r = call('POST', 'irongate_settings', ['blockchain_network' => 'mainnet', 'blockchain_indexer_url' => $good]);
check('V2 save: accept https URL on a known indexer host (control)', ($r['json']['success'] ?? null) === true
    && dbq("SELECT value FROM settings WHERE key='blockchain_indexer_url'") === $good, brief($r));
$local = 'http://127.0.0.1:8088/api/v4/graphql';
$r = call('POST', 'irongate_settings', ['blockchain_network' => 'undeployed', 'blockchain_indexer_url' => $local]);
check("V2 save: the selected network's own preset URL is accepted (control)", ($r['json']['success'] ?? null) === true
    && dbq("SELECT value FROM settings WHERE key='blockchain_indexer_url'") === $local, brief($r));
$r = call('POST', 'irongate_settings', ['blockchain_network' => 'preprod', 'blockchain_indexer_url' => $local]);
check("V2 save: another network's preset URL is not accepted for preprod", $r['status'] === 400, brief($r));
$r = call('POST', 'test_blockchain_connection', ['network' => 'preprod', 'indexer_url' => 'https://indexer.preview.midnight.network/api/v4/graphql']);
check('V2 probe: known indexer host is probed (control)', ($r['json']['success'] ?? null) === true
    && ($r['json']['endpoint'] ?? '') === 'https://indexer.preview.midnight.network/api/v4/graphql', brief($r));
$r = call('POST', 'test_blockchain_connection', ['network' => 'undeployed', 'indexer_url' => '']);
check('V2 probe: undeployed preset still used when no custom URL (control)', ($r['json']['success'] ?? null) === true
    && ($r['json']['endpoint'] ?? '') === 'http://127.0.0.1:8088/api/v4/graphql', brief($r));

// ---- V3: CORS -------------------------------------------------------------
foreach ([['GET', 'irongate_devices'], ['POST', 'irongate_devices'], ['OPTIONS', 'irongate_devices']] as [$m, $a]) {
    $r = call($m, $a, $m === 'POST' ? $dev('aa:00:00:00:00:30', '192.168.1.60', 'isolated') : null);
    $cors = array_values(array_filter($r['headers'], fn($h) => stripos($h, 'Access-Control-') === 0));
    $ct = array_values(array_filter($r['headers'], fn($h) => stripos($h, 'Content-Type:') === 0));
    check("V3 CORS: no Access-Control-* header on $m (headers were captured)", count($ct) === 1 && count($cors) === 0, json_encode($r['headers']));
}

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
