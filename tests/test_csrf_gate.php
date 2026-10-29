<?php
/**
 * Irongate web API: the CSRF gate covers every state-changing action.
 *
 * Every action that changes the configuration, the credentials, the access list, the DHCP service or the update
 * settings must refuse a request that carries a valid session but not that session's X-CSRF-Token, and accept the
 * request when the token is sent. The five actions that also serve a read-only GET (settings, device_groups,
 * irongate_devices, reservations, update_settings) stay exempt on GET only; apply, validate, update_check, start,
 * stop, restart and repair run on any method, GET included, and are gated unconditionally.
 *
 * Drives the real web/*.php over HTTP. It starts TWO built-in servers on 127.0.0.1:
 *   18141  no IRONGATE_TEST_SANDBOX in its environment, so irongate_test_sandbox() is false while php_sapi_name()
 *          is still 'cli-server' - the only way the gate is active under the built-in server. This is the server
 *          every gate assertion uses.
 *   18142  IRONGATE_TEST_SANDBOX=1, the seam the other PHP suites use: the bypass must be active there, i.e. the
 *          same untokened mutating request is NOT refused. That is the control that proves 18141 really exercises
 *          the gate and not a dead branch.
 *
 * Bodies are harmless: the actions are only ever asked with an empty or obviously-failing payload, and sudo,
 * systemctl, journalctl, logger and pkill are recording shims, so start/stop/restart/repair/apply cannot touch
 * anything real even inside a container.
 *
 * It creates /var/www/irongate/dhcp.db (the path api.php hardcodes), so it refuses to run outside a throw-away
 * sandbox:
 *
 *   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w php:8.3-cli php tests/test_csrf_gate.php web
 *
 * Exit status 0 = every case passed. Against the web/ of 5dfd152 it fails.
 */

if (PHP_SAPI !== 'cli') { exit(1); }
if (getenv('IRONGATE_TEST_SANDBOX') !== '1') {
    fwrite(STDERR, "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container\n");
    exit(2);
}
$webDir = realpath($argv[1] ?? 'web');
if ($webDir === false || !is_file("$webDir/api.php")) { fwrite(STDERR, "usage: php test_csrf_gate.php <web-dir>\n"); exit(2); }
$dbDir = '/var/www/irongate';
if (file_exists("$dbDir/dhcp.db") || file_exists("$dbDir/api.php")) {
    fwrite(STDERR, "refusing to run: $dbDir already holds an install\n");
    exit(2);
}

$work = '/tmp/ig-csrf-gate';
@mkdir("$work/sess", 0777, true);
@mkdir("$work/bin", 0777, true);
@mkdir("$work/webroot", 0777, true);
@mkdir($dbDir, 0777, true);
foreach (glob("$webDir/*.php") as $f) { copy($f, "$work/webroot/" . basename($f)); }

// Recording shims: every privileged call is logged and exits 0, nothing is executed.
foreach (['sudo', 'systemctl', 'journalctl', 'logger', 'pkill'] as $tool) {
    file_put_contents("$work/bin/$tool", "#!/bin/sh\necho \"$tool \$*\" >> $work/priv.log\nexit 0\n");
    chmod("$work/bin/$tool", 0755);
}
$baseEnv = ['PATH' => "$work/bin:" . getenv('PATH'), 'HOME' => '/tmp'];
$sandboxEnv = $baseEnv;
$sandboxEnv['IRONGATE_TEST_SANDBOX'] = '1';

$db = new SQLite3("$dbDir/dhcp.db");
$db->exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE reservations (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE NOT NULL, ip TEXT NOT NULL, hostname TEXT, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE irongate_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE NOT NULL, ip TEXT, hostname TEXT, zone TEXT DEFAULT 'isolated', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE device_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, color TEXT DEFAULT '#6c757d', icon TEXT, description TEXT, lan_access TEXT DEFAULT 'none', can_access_groups TEXT DEFAULT '[]', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    INSERT INTO settings VALUES ('irongate_enabled','false'), ('auto_update_enabled','false');");
$db->close();
chmod("$dbDir/dhcp.db", 0666);

function startServer($root, $port, $env, $work) {
    $srv = proc_open(['php', '-d', "session.save_path=$work/sess", '-S', "127.0.0.1:$port", '-t', $root],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', "$work/server-$port.log", 'w']], $sp, null, $env);
    register_shutdown_function(function () use ($srv) { if (is_resource($srv)) { proc_terminate($srv); proc_close($srv); } });
    for ($i = 0; $i < 50; $i++) {
        $c = @fsockopen('127.0.0.1', $port, $en, $es, 0.2);
        if ($c) { fclose($c); return true; }
        usleep(100000);
    }
    return false;
}

$pass = 0; $fail = 0;
function check($name, $cond, $detail = '') {
    global $pass, $fail;
    if ($cond) { $pass++; echo "PASS  $name\n"; }
    else { $fail++; echo "FAIL  $name" . ($detail !== '' ? "  -- $detail" : '') . "\n"; }
}

/** A real session file in the format of PHP's own handler ("php": key|serialize(value) per entry). */
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
    if ($body !== null) { $hdr .= "Content-Type: application/json\r\n"; }
    $ctx = stream_context_create(['http' => [
        'method' => $method, 'ignore_errors' => true, 'timeout' => 30, 'follow_location' => 0, 'max_redirects' => 0,
        'header' => $hdr, 'content' => $body === null ? '' : json_encode($body)]]);
    $raw = (string)@file_get_contents("http://127.0.0.1:$port$path", false, $ctx);
    $h = $http_response_header ?? [];
    preg_match('#^HTTP/\S+\s+(\d{3})#', $h[0] ?? '', $m);
    return ['status' => (int)($m[1] ?? 0), 'json' => json_decode($raw, true), 'raw' => $raw];
}
function brief($r) { return 'status=' . $r['status'] . ' body=' . substr(trim($r['raw']), 0, 160); }
function refusedByGate($r) {
    return $r['status'] === 403 && ($r['json']['success'] ?? null) === false
        && ($r['json']['error'] ?? '') === 'invalid csrf token';
}

// ====================================================================== static: the gate and its one bypass
$guard = (string)file_get_contents("$webDir/session_check.php");
preg_match('/function irongate_csrf_not_required\(\): bool \{(.*?)\n\}/s', $guard, $g);
$guardBody = trim(preg_replace('/\s+/', ' ', $g[1] ?? ''));
check('S irongate_csrf_not_required() is exactly `return irongate_test_sandbox();`', $guardBody === 'return irongate_test_sandbox();',
    'body=' . var_export($guardBody, true));

$api = (string)file_get_contents("$webDir/api.php");
preg_match('/\$IRONGATE_CSRF_ACTIONS = \[(.*?)\];/s', $api, $m1);
preg_match('/\$IRONGATE_CSRF_READ_ACTIONS = \[(.*?)\];/s', $api, $m2);
$gate = preg_match_all("/'([a-z_]+)'/", $m1[1] ?? '', $a) ? $a[1] : [];
$read = preg_match_all("/'([a-z_]+)'/", $m2[1] ?? '', $b) ? $b[1] : [];
sort($gate); sort($read);

$wantGate = ['apply', 'change_password', 'change_username', 'device_groups', 'irongate_apply', 'irongate_devices',
             'irongate_settings', 'irongate_toggle', 'repair', 'reservations', 'restart', 'settings', 'start', 'stop',
             'toggle_access_list', 'update_access_list', 'update_check', 'update_settings', 'validate'];
sort($wantGate);
$wantRead = ['device_groups', 'irongate_devices', 'reservations', 'settings', 'update_settings'];
sort($wantRead);
check('S api.php gates exactly the nineteen state-changing actions', $gate === $wantGate, implode(',', $gate));
check('S the read-only-GET exemption is exactly the five dual-purpose actions', $read === $wantRead, implode(',', $read));
$orphans = array_values(array_diff($read, $gate));
check('S every read-exempt action is also in the gate list (no dead exemption)', $orphans === [], implode(',', $orphans));

// ====================================================================== HTTP: gate server 18141 (sandbox var absent)
if (!startServer("$work/webroot", 18141, $baseEnv, $work)) { fwrite(STDERR, "built-in server 18141 did not start\n"); exit(2); }
if (!startServer("$work/webroot", 18142, $sandboxEnv, $work)) { fwrite(STDERR, "built-in server 18142 did not start\n"); exit(2); }

$tok = bin2hex(random_bytes(32));
$sid = authed($tok);
$sidNoTok = authed();

// Payloads are empty or obviously wrong on purpose: the handler may fail, the gate must not.
$bodies = [
    'apply' => [],
    'change_password' => ['current_password' => 'not-the-password', 'new_password' => 'newpassword1', 'confirm_password' => 'newpassword1'],
    'change_username' => ['current_password' => 'not-the-password', 'new_username' => 'someoneelse'],
    'device_groups' => [],
    'irongate_apply' => [],
    'irongate_devices' => [],
    'irongate_settings' => [],
    'irongate_toggle' => ['enabled' => false],
    'repair' => [],
    'reservations' => [],
    'restart' => [],
    'settings' => [],
    'start' => [],
    'stop' => [],
    'toggle_access_list' => ['enabled' => false],
    'update_access_list' => ['enabled' => false, 'allowed_ips' => ['127.0.0.1']],
    'update_check' => [],
    'update_settings' => [],
    'validate' => [],
];

// Every listed action, on a mutating method, with a valid session and no token: refused by the gate.
$missing = [];
foreach ($wantGate as $action) {
    $r = http(18141, 'POST', '/api.php?action=' . $action, ['cookie' => $sid, 'body' => $bodies[$action]]);
    if (!refusedByGate($r)) { $missing[] = "$action (" . brief($r) . ')'; }
}
check('G every gated action, POST, valid session, NO token: 403 {"success":false,"error":"invalid csrf token"}',
    $missing === [], implode(' | ', $missing));

// The same requests with the session's token: the gate lets them through (the handler may still fail).
$blocked = [];
foreach ($wantGate as $action) {
    $r = http(18141, 'POST', '/api.php?action=' . $action,
        ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok], 'body' => $bodies[$action]]);
    if ($r['status'] === 403 && ($r['json']['error'] ?? '') === 'invalid csrf token') { $blocked[] = "$action (" . brief($r) . ')'; }
}
check('G every gated action, POST, valid session + its token: not refused by the gate', $blocked === [], implode(' | ', $blocked));

// A session without a csrf_token at all has nothing to compare with: also refused (an old session is not a free pass).
$r = http(18141, 'POST', '/api.php?action=apply', ['cookie' => $sidNoTok, 'headers' => ['X-CSRF-Token' => $tok]]);
check('G a session that predates the token is refused even when a token is sent', refusedByGate($r), brief($r));

// The read-only GETs of the five dual-purpose actions stay exempt.
$exemptFail = [];
foreach ($wantRead as $action) {
    $r = http(18141, 'GET', '/api.php?action=' . $action, ['cookie' => $sid]);
    if ($r['status'] === 403 || ($r['json']['error'] ?? '') === 'invalid csrf token') { $exemptFail[] = "$action (" . brief($r) . ')'; }
}
check('G GET settings/device_groups/irongate_devices/reservations/update_settings, no token: not refused by the gate',
    $exemptFail === [], implode(' | ', $exemptFail));

// ... while an action that is gated on ANY method is gated on GET too (none of the seven is in the exemption).
$getGate = [];
foreach (['apply', 'validate', 'update_check', 'start', 'stop', 'restart', 'repair'] as $action) {
    $r = http(18141, 'GET', '/api.php?action=' . $action, ['cookie' => $sid]);
    if (!refusedByGate($r)) { $getGate[] = "$action (" . brief($r) . ')'; }
}
check('G GET apply/validate/update_check/start/stop/restart/repair, no token: refused by the gate',
    $getGate === [], implode(' | ', $getGate));

// ====================================================================== control: sandbox server 18142 (bypass active)
// Same request, same session, no token: with IRONGATE_TEST_SANDBOX=1 the bypass is active and the gate is silent.
// This proves the 18141 assertions above fail against a build where the gate is dead.
$bypassFail = [];
foreach (['apply', 'settings'] as $action) {
    $r = http(18142, 'POST', '/api.php?action=' . $action, ['cookie' => $sid, 'body' => $bodies[$action]]);
    if (refusedByGate($r)) { $bypassFail[] = "$action (" . brief($r) . ')'; }
}
check('G control: with IRONGATE_TEST_SANDBOX=1 the same untokened mutating request is NOT refused',
    $bypassFail === [], implode(' | ', $bypassFail));

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
