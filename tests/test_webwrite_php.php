<?php
/**
 * irongate web tier -> root helper: the PHP side.
 *
 * Drives the real web/*.php over HTTP (php -S), with real session files, a recording `sudo` on PATH and a
 * deterministic `ip` so the generator is reproducible. Two servers:
 *   18201  cli-server + IRONGATE_TEST_SANDBOX=1  - the PHP suites' seam: old direct writes, CSRF gate off
 *   18202  the same files with PHP_SAPI rewritten to fpm-fcgi - the deployed shape: the CSRF gate is on and
 *          config/credential writes go through /usr/local/sbin/irongate-webwrite (the recording sudo)
 *
 * Cases
 *   CSRF     settings, irongate_toggle, irongate_apply, device_groups, irongate_devices, change_password,
 *            change_username, update_access_list, toggle_access_list: session without a token -> 403
 *            {"success":false,"error":"invalid csrf token"}; with the session's token -> not 403
 *   helper   config-apply and the two auth verbs are invoked as `sudo -n /usr/local/sbin/irongate-webwrite
 *            <verb>`, the JSON on stdin carries the settings / only the hash / only the username, and
 *            /etc/irongate/config.yaml and auth.json are NOT written by PHP; a failing helper surfaces the
 *            same user-facing error text as before
 *   parity   the seam's generator output for the fixture equals tests/fixtures/webwrite-parity-config.yaml
 *            (the Python suite renders the same fixture through the helper and compares to that file)
 *   login    lockout counters live in /var/lib/irongate/lockout/lockout.json (global keying, same thresholds
 *            and messages), auth.json is read-only on the login path, and the counter file is locked
 *
 * It overwrites /var/www/irongate, /etc/irongate and /var/lib/irongate/lockout, so it refuses to run outside
 * a throw-away sandbox:
 *
 *   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w php:8.3-cli \
 *       php tests/test_webwrite_php.php web
 *
 * Exit status 0 = every case passed. Against the web/ of bcab19c it fails.
 */

if (PHP_SAPI !== 'cli') { exit(1); }
if (getenv('IRONGATE_TEST_SANDBOX') !== '1') {
    fwrite(STDERR, "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container\n");
    exit(2);
}
$webDir = realpath($argv[1] ?? 'web');
$docroot = '/var/www/irongate';
if ($webDir === false || !is_file("$webDir/api.php")) { fwrite(STDERR, "usage: php test_webwrite_php.php <web-dir>\n"); exit(2); }
if (file_exists("$docroot/dhcp.db")) { fwrite(STDERR, "refusing to run: $docroot/dhcp.db already exists\n"); exit(2); }

$work = '/tmp/ig-webwrite';
@mkdir("$work/sess", 0777, true);
@mkdir("$work/bin", 0777, true);
@mkdir("$work/fpmroot", 0777, true);
@mkdir($docroot, 0777, true);
@mkdir('/etc/irongate', 0750, true);
@mkdir('/var/lib/irongate/lockout', 0700, true);
foreach (glob("$webDir/*.php") as $f) { copy($f, "$docroot/" . basename($f)); }

// ---- a recording sudo: logs the command, saves webwrite stdin, emits the helper's JSON ------------------
file_put_contents("$work/bin/sudo", <<<'SH'
#!/bin/sh
echo "sudo $*" >> /tmp/ig-webwrite/sudo.log
verb=""
case "$*" in
    *irongate-webwrite\ config-apply) verb=config-apply ;;
    *irongate-webwrite\ auth-set-credentials) verb=auth-set-credentials ;;
    *irongate-webwrite\ auth-set-username) verb=auth-set-username ;;
esac
rc=0
if [ -f /tmp/ig-webwrite/sudo.rc ]; then rc=$(cat /tmp/ig-webwrite/sudo.rc); fi
if [ -n "$verb" ]; then
    cat > "/tmp/ig-webwrite/stdin-$verb.json"
    if [ "$rc" = "0" ]; then
        printf '{"success":true,"error":"","changed":true}\n'
    else
        printf '{"success":false,"error":"refused","changed":false}\n'
    fi
fi
exit "$rc"
SH
);
chmod("$work/bin/sudo", 0755);

// ---- deterministic ip ------------------------------------------------------------------------------------
file_put_contents("$work/bin/ip", <<<'SH'
#!/bin/sh
case "$*" in
    "route") echo "default via 192.168.1.1 dev eth0 proto static"; echo "192.168.1.0/24 dev eth0 scope link" ;;
    *"addr show eth0"*) echo "    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0" ;;
    *"link show eth0"*) echo "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500"; echo "    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff" ;;
    "neigh show") echo "192.168.1.1 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE" ;;
    *) : ;;
esac
SH
);
chmod("$work/bin/ip", 0755);

$baseEnv = ['PATH' => "$work/bin:" . getenv('PATH'), 'HOME' => '/tmp', 'TZ' => 'UTC'];
$seamEnv = $baseEnv + ['IRONGATE_TEST_SANDBOX' => '1'];
$fpmEnv = $baseEnv;

function startServer($root, $port, $env, $work) {
    $srv = proc_open(['php', '-d', "session.save_path=$work/sess", '-S', "127.0.0.1:$port", '-t', $root],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', "$work/server-$port.log", 'w']],
        $pipes, null, $env);
    register_shutdown_function(function () use ($srv) { if (is_resource($srv)) { proc_terminate($srv); proc_close($srv); } });
    for ($i = 0; $i < 50; $i++) {
        $c = @fsockopen('127.0.0.1', $port, $en, $es, 0.2);
        if ($c) { fclose($c); return true; }
        usleep(100000);
    }
    return false;
}
if (!startServer($docroot, 18201, $seamEnv, $work)) { fwrite(STDERR, "built-in server 18201 did not start\n"); exit(2); }

$pass = 0; $fail = 0;
function check($name, $cond, $detail = '') {
    global $pass, $fail;
    if ($cond) { $pass++; echo "PASS  $name\n"; }
    else { $fail++; echo "FAIL  $name" . ($detail !== '' ? "  -- $detail" : '') . "\n"; }
}

// ---- the database the generator reads ----------------------------------------------------------------
$db = new SQLite3("$docroot/dhcp.db");
$db->exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE irongate_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE NOT NULL, ip TEXT, hostname TEXT, zone TEXT DEFAULT 'isolated', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE device_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, color TEXT DEFAULT '#6c757d', icon TEXT, description TEXT, lan_access TEXT DEFAULT 'none', can_access_groups TEXT DEFAULT '[]', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);");
$fixture = [
    'irongate_enabled' => 'true',
    'irongate_mode' => 'dual',
    'interface' => 'eth0',
    'gateway' => '192.168.1.1',
    'irongate_isolated_interface' => 'eth1',
    'irongate_bridge_ip' => '10.99.0.1',
    'irongate_bridge_dhcp_start' => '10.99.1.1',
    'irongate_bridge_dhcp_end' => '10.99.255.254',
    'irongate_arp_defense' => 'true',
    'irongate_ipv6_ra' => 'true',
    'irongate_gateway_takeover' => 'true',
    'irongate_bypass_detection' => 'true',
    'irongate_firewall' => 'true',
    'blockchain_enabled' => 'true',
    'blockchain_network' => 'preprod',
    'blockchain_contract_address' => '0x' . str_repeat('ab', 32),
    'blockchain_indexer_url' => 'https://indexer.preprod.midnight.network/api/v4/graphql',
    'blockchain_cache_ttl' => '60',
    'blockchain_fallback_allow' => 'true',
    'blockchain_audit_logging' => 'false',
    'blockchain_allow_rogue_devices' => 'false',
];
$stmt = $db->prepare('INSERT INTO settings (key, value) VALUES (?, ?)');
foreach ($fixture as $k => $v) { $stmt->bindValue(1, $k, SQLITE3_TEXT); $stmt->bindValue(2, $v, SQLITE3_TEXT); $stmt->execute(); }
$db->exec("INSERT INTO device_groups (name, color, icon, description, lan_access, can_access_groups)
           VALUES ('cams', '#6c757d', '📁', 'front cameras', 'selected', '[\"servers\",\"trusted\"]')");
$db->exec("INSERT INTO irongate_devices (mac, ip, hostname, zone) VALUES
           ('aa:bb:cc:dd:ee:01', '192.168.1.10', 'camera1', 'cams'),
           ('aa:bb:cc:dd:ee:02', '', '', 'isolated')");
$db->close();
chmod("$docroot/dhcp.db", 0666);

function dbq($sql) {
    global $docroot;
    $d = new SQLite3("$docroot/dhcp.db", SQLITE3_OPEN_READONLY);
    $r = $d->querySingle($sql);
    $d->close();
    return $r;
}

function mkSession(array $data) {
    global $work;
    $id = bin2hex(random_bytes(16));
    $enc = '';
    foreach ($data as $k => $v) { $enc .= $k . '|' . serialize($v); }
    file_put_contents("$work/sess/sess_$id", $enc);
    chmod("$work/sess/sess_$id", 0600);
    return $id;
}
function authed($csrf = null) {
    $d = ['authenticated' => true, 'username' => 'admin', 'last_activity' => time()];
    if ($csrf !== null) { $d['csrf_token'] = $csrf; }
    return mkSession($d);
}

function http($port, $method, $path, $opt = []) {
    $hdr = '';
    if (!empty($opt['cookie'])) { $hdr .= 'Cookie: PHPSESSID=' . $opt['cookie'] . "\r\n"; }
    foreach (($opt['headers'] ?? []) as $k => $v) { $hdr .= "$k: $v\r\n"; }
    $body = $opt['body'] ?? null;
    $form = $opt['form'] ?? null;
    $timeout = $opt['timeout'] ?? 30;
    if ($form !== null) {
        $hdr .= "Content-Type: application/x-www-form-urlencoded\r\n";
        $content = http_build_query($form);
    } elseif ($body !== null) {
        $hdr .= "Content-Type: application/json\r\n";
        $content = json_encode($body);
    } else {
        $content = '';
    }
    $ctx = stream_context_create(['http' => [
        'method' => $method, 'ignore_errors' => true, 'timeout' => $timeout, 'follow_location' => 0, 'max_redirects' => 0,
        'header' => $hdr, 'content' => $content]]);
    $raw = @file_get_contents("http://127.0.0.1:$port$path", false, $ctx);
    $h = $http_response_header ?? [];
    preg_match('#^HTTP/\S+\s+(\d{3})#', $h[0] ?? '', $m);
    return ['status' => (int)($m[1] ?? 0), 'json' => json_decode((string)$raw, true), 'raw' => (string)$raw, 'headers' => $h];
}
function brief($r) { return 'status=' . $r['status'] . ' body=' . substr(trim($r['raw']), 0, 160); }
function sudoLog() { global $work; return is_file("$work/sudo.log") ? file_get_contents("$work/sudo.log") : ''; }
function sudoReset($rc = 0) {
    global $work;
    @unlink("$work/sudo.log");
    @unlink("$work/stdin-config-apply.json");
    @unlink("$work/stdin-auth-set-credentials.json");
    @unlink("$work/stdin-auth-set-username.json");
    if ($rc === 0) { @unlink("$work/sudo.rc"); } else { file_put_contents("$work/sudo.rc", (string)$rc); }
}
function helperCalls($verb) {
    return substr_count(sudoLog(), "/usr/local/sbin/irongate-webwrite $verb\n");
}
function writeFile($path, $data, $mode = 0640, $uid = 0, $gid = 33) {
    file_put_contents($path, $data);
    chown($path, $uid); chgrp($path, $gid); chmod($path, $mode);
}
function fileSig($path) { clearstatcache(true, $path); return is_file($path) ? sha1_file($path) . ':' . filemtime($path) . ':' . filesize($path) : 'missing'; }

// ====================================================================== A: the seam generator (+ parity golden)
sudoReset();
@unlink('/etc/irongate/config.yaml');
$r = http(18201, 'POST', '/api.php?action=irongate_apply');
check('A seam (cli-server + IRONGATE_TEST_SANDBOX=1): irongate_apply regenerates config.yaml directly (200)',
    $r['status'] === 200 && ($r['json']['success'] ?? null) === true, brief($r));
check('A ... and the helper was not involved (the seam keeps the old direct write)', helperCalls('config-apply') === 0, sudoLog());
$phpConfig = (string)@file_get_contents('/etc/irongate/config.yaml');
check('A the generated config has the generator\'s first line and the dual-NIC bridge block',
    strpos($phpConfig, "# Irongate Configuration\n") === 0 && strpos($phpConfig, "  bridge_name: \"br-irongate\"\n") !== false
    && strpos($phpConfig, "  port_isolation: true\n") !== false);
$normalized = preg_replace('/^# Generated: .*$/m', '# Generated: X', $phpConfig);
file_put_contents("$work/php-config-normalized.yaml", $normalized);
if (getenv('IG_OUT')) {
    @mkdir((string)getenv('IG_OUT'), 0777, true);
    file_put_contents(rtrim((string)getenv('IG_OUT'), '/') . '/php-config-normalized.yaml', $normalized);
}
$fixturePath = dirname(__DIR__) . '/tests/fixtures/webwrite-parity-config.yaml';
if (is_file($fixturePath)) {
    $want = (string)file_get_contents($fixturePath);
    check('A parity: the seam generator output (Generated line normalised) equals tests/fixtures/webwrite-parity-config.yaml',
        $normalized === $want, 'php ' . strlen($normalized) . ' bytes, fixture ' . strlen($want));
} else {
    check('A parity: tests/fixtures/webwrite-parity-config.yaml exists', false, 'missing');
}

// ====================================================================== B: fpm shape - CSRF gate
foreach (glob("$webDir/*.php") as $f) { copy($f, "$work/fpmroot/" . basename($f)); }
$guard = (string)file_get_contents("$work/fpmroot/session_check.php");
check('B setup: session_check.php can be told it runs under php-fpm (exactly one literal PHP_SAPI)',
    substr_count($guard, 'PHP_SAPI') === 1);
file_put_contents("$work/fpmroot/session_check.php", str_replace('PHP_SAPI', "'fpm-fcgi'", $guard));
if (!startServer("$work/fpmroot", 18202, $fpmEnv, $work)) { fwrite(STDERR, "built-in server 18202 did not start\n"); exit(2); }

$src = (string)@file_get_contents("$webDir/session_check.php");
check('B session_check.php defines the one sandbox gate and the CSRF require function',
    strpos($src, 'function irongate_test_sandbox()') !== false
    && strpos($src, 'function irongate_csrf_not_required()') !== false
    && strpos($src, 'function irongate_require_csrf()') !== false
    && strpos($src, "php_sapi_name() === 'cli-server'") !== false
    && strpos($src, "getenv('IRONGATE_TEST_SANDBOX') === '1'") !== false);
$api = (string)@file_get_contents("$webDir/api.php");
preg_match('/\$IRONGATE_CSRF_ACTIONS = \[(.*?)\];/s', $api, $mm);
$gateActions = [];
if (isset($mm[1]) && preg_match_all("/'([a-z_]+)'/", $mm[1], $aa)) { $gateActions = $aa[1]; }
sort($gateActions);
$wantActions = ['change_password', 'change_username', 'device_groups', 'irongate_apply', 'irongate_devices',
                'irongate_settings', 'irongate_toggle', 'settings', 'toggle_access_list', 'update_access_list'];
sort($wantActions);
check('B api.php gates exactly the ten state-changing actions', $gateActions === $wantActions, implode(',', $gateActions));

$tok = bin2hex(random_bytes(32));
$sid = authed($tok);
$bodies = [
    'settings' => [],
    'irongate_toggle' => ['enabled' => true],
    'irongate_apply' => [],
    'device_groups' => ['name' => 'g1', 'lan_access' => 'none'],
    'irongate_devices' => ['mac' => 'aa:bb:cc:dd:ee:09', 'ip' => '192.168.1.9', 'zone' => 'isolated'],
    'change_password' => ['current_password' => 'oldpassword', 'new_password' => 'newpassword1', 'confirm_password' => 'newpassword1'],
    'change_username' => ['current_password' => 'oldpassword', 'new_username' => 'newadmin'],
    'update_access_list' => ['enabled' => false, 'allowed_ips' => ['127.0.0.1']],
    'toggle_access_list' => ['enabled' => false],
];
$allNoToken = true; $allWithToken = true;
foreach ($bodies as $action => $body) {
    $r = http(18202, 'POST', "/api.php?action=$action", ['cookie' => $sid, 'body' => $body]);
    $ok = $r['status'] === 403 && ($r['json']['success'] ?? null) === false && ($r['json']['error'] ?? '') === 'invalid csrf token';
    if (!$ok) { $allNoToken = false; echo "  (no-token $action: " . brief($r) . ")\n"; }
}
check('B every gated action, valid session but NO token: 403 {"success":false,"error":"invalid csrf token"}', $allNoToken);
foreach ($bodies as $action => $body) {
    $r = http(18202, 'POST', "/api.php?action=$action", ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok], 'body' => $body]);
    $ok = $r['status'] !== 403;
    if (!$ok) { $allWithToken = false; echo "  (with-token $action: " . brief($r) . ")\n"; }
}
check('B every gated action, valid session + its token: not 403', $allWithToken);

// The dashboard's main config writer ("Save & Apply" / the Blockchain save) is a separate action from the
// DHCP 'settings' one; it must be gated too (and is POST-only, so it is not in the GET exemption).
$r = http(18202, 'POST', '/api.php?action=irongate_settings', ['cookie' => $sid, 'body' => []]);
check('B irongate_settings, valid session but NO token: 403 {"success":false,"error":"invalid csrf token"}',
    $r['status'] === 403 && ($r['json']['error'] ?? '') === 'invalid csrf token', brief($r));
$r = http(18202, 'POST', '/api.php?action=irongate_settings', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok], 'body' => []]);
check('B irongate_settings, valid session + its token: not 403', $r['status'] !== 403, brief($r));

// ====================================================================== C: helper invocation, no direct writes
writeFile('/etc/irongate/auth.json', json_encode([
    'username' => 'admin',
    'password_hash' => password_hash('oldpassword', PASSWORD_BCRYPT),
    'created_at' => '2026-01-01T00:00:00+00:00',
    'updated_at' => '2026-01-01T00:00:00+00:00',
    'failed_attempts' => 0, 'first_failed_at' => 0, 'locked_until' => 0,
], JSON_PRETTY_PRINT) . "\n");

writeFile('/etc/irongate/config.yaml', "# Irongate Configuration\n# Generated: 2026-01-01 00:00:00\n\nold: true\n");
$configSig = fileSig('/etc/irongate/config.yaml');
$authSig = fileSig('/etc/irongate/auth.json');

sudoReset();
$r = http(18202, 'POST', '/api.php?action=irongate_apply', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok]]);
check('C irongate_apply under fpm-fcgi: 200 success', $r['status'] === 200 && ($r['json']['success'] ?? null) === true, brief($r));
check('C ... `sudo -n /usr/local/sbin/irongate-webwrite config-apply` was called exactly once', helperCalls('config-apply') === 1, sudoLog());
$stdin = is_file("$work/stdin-config-apply.json") ? json_decode((string)file_get_contents("$work/stdin-config-apply.json"), true) : null;
check('C ... the JSON on stdin is {"settings":{...}} with the generator\'s key set (network, mode, bridge, layers, blockchain, custom_groups, devices)',
    is_array($stdin) && array_keys($stdin) === ['settings']
    && array_keys($stdin['settings']) == ['network', 'mode', 'layers', 'blockchain', 'custom_groups', 'devices', 'bridge']
    && array_keys($stdin['settings']['network']) == ['interface', 'local_ip', 'local_mac', 'gateway_ip', 'gateway_mac'],
    substr((string)json_encode($stdin), 0, 200));
check('C ... and no YAML text is ever handed to the helper', strpos((string)file_get_contents("$work/stdin-config-apply.json"), '# Irongate Configuration') === false);
check('C PHP did NOT write /etc/irongate/config.yaml itself (bytes and mtime unchanged)', fileSig('/etc/irongate/config.yaml') === $configSig,
    fileSig('/etc/irongate/config.yaml') . ' vs ' . $configSig);

sudoReset();
$r = http(18202, 'POST', '/api.php?action=change_password', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok],
    'body' => ['current_password' => 'oldpassword', 'new_password' => 'newpassword1', 'confirm_password' => 'newpassword1']]);
check('C change_password under fpm-fcgi: 200 "Password changed"', $r['status'] === 200 && ($r['json']['message'] ?? '') === 'Password changed', brief($r));
check('C ... auth-set-credentials was called once', helperCalls('auth-set-credentials') === 1, sudoLog());
$stdin = is_array(json_decode((string)@file_get_contents("$work/stdin-auth-set-credentials.json"), true))
    ? json_decode((string)file_get_contents("$work/stdin-auth-set-credentials.json"), true) : null;
check('C ... the JSON on stdin carries ONLY a bcrypt password_hash, never the plaintext',
    is_array($stdin) && array_keys($stdin) === ['password_hash']
    && preg_match('/^\$2[aby]\$\d\d\$[.\/A-Za-z0-9]{53}$/', $stdin['password_hash']) === 1
    && strpos((string)file_get_contents("$work/stdin-auth-set-credentials.json"), 'newpassword1') === false, json_encode($stdin));
check('C PHP did NOT write /etc/irongate/auth.json itself (bytes and mtime unchanged)', fileSig('/etc/irongate/auth.json') === $authSig,
    fileSig('/etc/irongate/auth.json') . ' vs ' . $authSig);

sudoReset();
$r = http(18202, 'POST', '/api.php?action=change_username', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok],
    'body' => ['current_password' => 'oldpassword', 'new_username' => 'newadmin']]);
check('C change_username under fpm-fcgi: 200 "Username changed"', $r['status'] === 200 && ($r['json']['message'] ?? '') === 'Username changed', brief($r));
check('C ... auth-set-username was called once', helperCalls('auth-set-username') === 1, sudoLog());
$stdin = json_decode((string)@file_get_contents("$work/stdin-auth-set-username.json"), true);
check('C ... the JSON on stdin carries ONLY the new username', is_array($stdin) && $stdin === ['username' => 'newadmin'], json_encode($stdin));
check('C PHP did NOT write /etc/irongate/auth.json itself (change_username)', fileSig('/etc/irongate/auth.json') === $authSig);

sudoReset(2);
$r = http(18202, 'POST', '/api.php?action=irongate_apply', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok]]);
check('C helper refuses (exit 2): config-apply surfaces the existing user-facing error text',
    $r['status'] === 200 && ($r['json']['success'] ?? null) === false
    && ($r['json']['error'] ?? '') === 'Failed to write config file - check /etc/irongate permissions', brief($r));
$r = http(18202, 'POST', '/api.php?action=change_password', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok],
    'body' => ['current_password' => 'oldpassword', 'new_password' => 'newpassword1', 'confirm_password' => 'newpassword1']]);
check('C helper refuses (exit 2): change_password surfaces the existing user-facing error text',
    ($r['json']['success'] ?? null) === false && ($r['json']['error'] ?? '') === 'Failed to write auth config', brief($r));
sudoReset();

// ====================================================================== D: login lockout state
$lockout = '/var/lib/irongate/lockout/lockout.json';
function lockState($path) { clearstatcache(true, $path); $d = json_decode((string)@file_get_contents($path), true); return is_array($d) ? $d : null; }
function loginGet($port) {
    $r = http($port, 'GET', '/login.php');
    $sid = null;
    foreach ($r['headers'] as $h) {
        if (stripos($h, 'Set-Cookie:') === 0 && preg_match('/PHPSESSID=([^;]+)/', $h, $m)) { $sid = $m[1]; }
    }
    preg_match('/name="csrf_token" value="([0-9a-f]{64})"/', $r['raw'], $m);
    return ['sid' => $sid, 'token' => $m[1] ?? null, 'raw' => $r['raw'], 'status' => $r['status']];
}
function loginPost($port, $sid, $token, $user, $pass, $timeout = 30) {
    return http($port, 'POST', '/login.php', ['cookie' => $sid, 'timeout' => $timeout,
        'form' => ['csrf_token' => $token, 'username' => $user, 'password' => $pass]]);
}
writeFile($lockout, '{"version":1,"failed_attempts":0,"first_failed_at":0,"locked_until":0}' . "\n", 0600, 33, 33);
$authBefore = fileSig('/etc/irongate/auth.json');
$login = loginGet(18201);
check('D login page: a session cookie and its CSRF token are issued', $login['sid'] !== null && $login['token'] !== null, 'sid=' . var_export($login['sid'], true));

$r = loginPost(18201, $login['sid'], $login['token'], 'admin', 'wrong-password');
$st = lockState($lockout);
check('D a failed login increments failed_attempts in the lockout file (1)', $r['status'] === 200 && strpos($r['raw'], 'Invalid username or password.') !== false
    && is_array($st) && (int)$st['failed_attempts'] === 1 && (int)$st['first_failed_at'] > 0, brief($r) . ' state=' . json_encode($st));
$r = loginPost(18201, $login['sid'], $login['token'], 'admin', 'wrong-password');
$st = lockState($lockout);
check('D a second failed login persists across requests (2)', is_array($st) && (int)$st['failed_attempts'] === 2, 'state=' . json_encode($st));
check('D auth.json is READ ONLY on the login path (bytes and mtime unchanged)', fileSig('/etc/irongate/auth.json') === $authBefore,
    fileSig('/etc/irongate/auth.json') . ' vs ' . $authBefore);

loginPost(18201, $login['sid'], $login['token'], 'admin', 'wrong-password');
loginPost(18201, $login['sid'], $login['token'], 'admin', 'wrong-password');
$r = loginPost(18201, $login['sid'], $login['token'], 'admin', 'wrong-password');
$st = lockState($lockout);
check('D the fifth failure sets locked_until (15 minutes) and resets the attempt counter, same message as before',
    strpos($r['raw'], 'Too many failed attempts. Locked for 15 minutes.') !== false && is_array($st)
    && (int)$st['locked_until'] > time() && (int)$st['failed_attempts'] === 0 && (int)$st['first_failed_at'] === 0,
    'state=' . json_encode($st));
$before = $st;
$r = loginPost(18201, $login['sid'], $login['token'], 'admin', 'oldpassword');
$st = lockState($lockout);
check('D while locked, even the correct password is refused with the "Try again in N minute(s)" message',
    strpos($r['raw'], 'Too many failed attempts. Try again in') !== false && $st === $before, 'state=' . json_encode($st));

writeFile($lockout, '{"version":1,"failed_attempts":2,"first_failed_at":' . (time() - 5) . ',"locked_until":0}' . "\n", 0600, 33, 33);
$r = loginPost(18201, $login['sid'], $login['token'], 'admin', 'oldpassword');
$st = lockState($lockout);
check('D a successful login resets the counters (and redirects)', $r['status'] === 302 && is_array($st)
    && (int)$st['failed_attempts'] === 0 && (int)$st['first_failed_at'] === 0 && (int)$st['locked_until'] === 0,
    brief($r) . ' state=' . json_encode($st));
check('D auth.json is STILL unchanged after the whole lockout flow', fileSig('/etc/irongate/auth.json') === $authBefore);

// the counter file is locked exclusively: while the test holds the lock, a login request cannot complete
writeFile($lockout, '{"version":1,"failed_attempts":0,"first_failed_at":0,"locked_until":0}' . "\n", 0600, 33, 33);
$login = loginGet(18201);
$hold = fopen($lockout, 'c+');
$locked = $hold !== false && flock($hold, LOCK_EX);
$r = $locked ? loginPost(18201, $login['sid'], $login['token'], 'admin', 'wrong-password', 0.6) : ['status' => -1];
check('D the login path takes flock(LOCK_EX) on the counter file (a held lock blocks the request)', $locked && $r['status'] === 0,
    'status=' . $r['status']);
if ($locked) { flock($hold, LOCK_UN); fclose($hold); }
usleep(300000);
$r = loginGet(18201);
check('D after the lock is released the login page is served again (control)', $r['status'] === 200 && $r['token'] !== null);

// ====================================================================== E: no direct write to /etc/irongate remains
$fpmApi = (string)@file_get_contents("$work/fpmroot/api.php");
check('E api.php writes config.yaml/auth.json only inside the seam branches (one config write, the two auth writes)',
    substr_count($fpmApi, "file_put_contents('/etc/irongate/config.yaml'") === 1
    && substr_count($fpmApi, "file_put_contents('/etc/irongate/auth.json'") === 2);
check('E api.php no longer runs `sudo systemctl restart irongate` (the helper restarts only on change)',
    strpos($fpmApi, 'sudo systemctl restart irongate') === false);

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
