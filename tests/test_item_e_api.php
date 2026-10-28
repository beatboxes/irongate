<?php
/**
 * Irongate web API hardening (item E): update_now needs a session AND a CSRF token, starts the update through the one
 * sudo rule the installer grants, and the localhost session bypass exists only under PHP's built-in server.
 *
 * Drives the real web/*.php end to end over HTTP (php -S on 127.0.0.1) with real session files and a recording `sudo`
 * on PATH, and checks the HTTP status, the JSON answer, what sudo was asked to run, and what landed in the database.
 *
 *   C1  update_now: no cookie, no token, wrong token, another session's token -> 403 and sudo is not asked to start anything;
 *       a valid session + its token -> `sudo -n /usr/bin/systemctl start --no-block irongate-updater-now.service` (and never
 *       `irongate-updater.sh --force`); a failing sudo -> HTTP 500; GET stays 405
 *   C2  irongate_local_bypass_allowed(): true only for cli-server on loopback without a session cookie
 *   C2  with the guard told it runs under php-fpm (fpm-fcgi) a loopback request without a cookie is 401 on every endpoint
 *       tried (read, state-changing, update_now); the built-in server still honours the bypass (control: the other suites
 *       drive api.php that way)
 *   C1  index.php hands the session's CSRF token to the page (meta tag) and the api() helper sends it; a session that
 *       predates the token gets one; an anonymous visitor gets neither a page nor a token
 *
 * It overwrites /var/www/irongate and starts PHP's built-in web server on 127.0.0.1:18101 and :18102, so it refuses to
 * run outside a throw-away sandbox:
 *
 *   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -v "$PWD":/w:ro -w /w php:8.3-cli php tests/test_item_e_api.php web
 *
 * Exit status 0 = every case passed. Against the web/ of c866e4c it fails.
 */

if (PHP_SAPI !== 'cli') { exit(1); }
if (getenv('IRONGATE_TEST_SANDBOX') !== '1') {
    fwrite(STDERR, "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container\n");
    exit(2);
}
$webDir = realpath($argv[1] ?? 'web');
$docroot = '/var/www/irongate';
if ($webDir === false || !is_file("$webDir/api.php")) { fwrite(STDERR, "usage: php test_item_e_api.php <web-dir>\n"); exit(2); }
if (file_exists("$docroot/dhcp.db")) { fwrite(STDERR, "refusing to run: $docroot/dhcp.db already exists\n"); exit(2); }

$work = '/tmp/ig-item-e';
@mkdir("$work/sess", 0777, true);
@mkdir("$work/bin", 0777, true);
@mkdir("$work/fpmroot", 0777, true);
@mkdir($docroot, 0777, true);
foreach (glob("$webDir/*.php") as $f) { copy($f, "$docroot/" . basename($f)); }

// A recording sudo: the update line exits with the status in sudo.rc (default 0); everything else (touch, chown, ...) is only logged.
file_put_contents("$work/bin/sudo", "#!/bin/sh\necho \"sudo \$*\" >> $work/sudo.log\ncase \"\$*\" in *irongate-updater-now.service*) exit \$(cat $work/sudo.rc 2>/dev/null || echo 0) ;; esac\nexit 0\n");
chmod("$work/bin/sudo", 0755);
$env = ['PATH' => "$work/bin:" . getenv('PATH'), 'HOME' => '/tmp'];

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
if (!startServer($docroot, 18101, $env, $work)) { fwrite(STDERR, "built-in server did not start\n"); exit(2); }

$pass = 0; $fail = 0;
function check($name, $cond, $detail = '') {
    global $pass, $fail;
    if ($cond) { $pass++; echo "PASS  $name\n"; }
    else { $fail++; echo "FAIL  $name" . ($detail !== '' ? "  -- $detail" : '') . "\n"; }
}

$db = new SQLite3("$docroot/dhcp.db");
$db->exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE reservations (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE NOT NULL, ip TEXT NOT NULL, hostname TEXT, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE irongate_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT UNIQUE NOT NULL, ip TEXT, hostname TEXT, zone TEXT DEFAULT 'isolated', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE device_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, color TEXT DEFAULT '#6c757d', icon TEXT, description TEXT, lan_access TEXT DEFAULT 'none', can_access_groups TEXT DEFAULT '[]', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
    INSERT INTO settings VALUES ('irongate_enabled','false'), ('auto_update_enabled','false');");
$db->close();
chmod("$docroot/dhcp.db", 0666);

function dbq($sql) {
    global $docroot;
    $d = new SQLite3("$docroot/dhcp.db", SQLITE3_OPEN_READONLY);
    $r = $d->querySingle($sql);
    $d->close();
    return $r;
}

/** A real session file in the format of PHP's own session handler ("php": key|serialize(value) per entry). */
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
    return ['status' => (int)($m[1] ?? 0), 'json' => json_decode($raw, true), 'raw' => $raw, 'headers' => $h];
}
function brief($r) { return 'status=' . $r['status'] . ' body=' . substr(trim($r['raw']), 0, 160); }
function sudoLog() { global $work; return is_file("$work/sudo.log") ? file_get_contents("$work/sudo.log") : ''; }
function sudoReset($rc = 0) { global $work; @unlink("$work/sudo.log"); file_put_contents("$work/sudo.rc", (string)$rc); }
$START = 'sudo -n /usr/bin/systemctl start --no-block irongate-updater-now.service';
function started() { global $START; return substr_count(sudoLog(), $START . "\n"); }
function anyUpdaterRun() { return strpos(sudoLog(), 'irongate-updater.sh') !== false || strpos(sudoLog(), '--force') !== false; }

// ============================================================================ C1: update_now
$tok = bin2hex(random_bytes(32));
$sid = authed($tok);

sudoReset();
$r = http(18101, 'POST', '/api.php?action=update_now', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok]]);
check('C1 valid session + its CSRF token: 200 success', $r['status'] === 200 && ($r['json']['success'] ?? null) === true, brief($r));
check('C1 ... sudo was asked to run exactly `sudo -n /usr/bin/systemctl start --no-block irongate-updater-now.service`, once',
    started() === 1, 'sudo.log: ' . str_replace("\n", ' | ', sudoLog()));
check('C1 ... and nothing launched the updater script or --force itself', !anyUpdaterRun(), 'sudo.log: ' . str_replace("\n", ' | ', sudoLog()));

sudoReset();
$r = http(18101, 'POST', '/api.php?action=update_now', ['cookie' => $sid]);
check('C1 valid session, NO CSRF token: 403 JSON, nothing started', $r['status'] === 403 && ($r['json']['success'] ?? null) === false && started() === 0 && !anyUpdaterRun(), brief($r) . ' sudo.log: ' . sudoLog());

sudoReset();
$r = http(18101, 'POST', '/api.php?action=update_now', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => str_repeat('0', 64)]]);
check('C1 valid session, WRONG token: 403, nothing started', $r['status'] === 403 && started() === 0 && !anyUpdaterRun(), brief($r));

sudoReset();
$r = http(18101, 'POST', '/api.php?action=update_now', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => '']]);
check('C1 valid session, EMPTY token header: 403, nothing started', $r['status'] === 403 && started() === 0, brief($r));

sudoReset();
$r = http(18101, 'POST', '/api.php?action=update_now', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => substr($tok, 0, 63)]]);
check('C1 valid session, token one character short: 403, nothing started', $r['status'] === 403 && started() === 0, brief($r));

$sidOther = authed(bin2hex(random_bytes(32)));
sudoReset();
$r = http(18101, 'POST', '/api.php?action=update_now', ['cookie' => $sidOther, 'headers' => ['X-CSRF-Token' => $tok]]);
check("C1 another session's token does not open this session: 403, nothing started", $r['status'] === 403 && started() === 0, brief($r));

$sidNoTok = authed(null);
sudoReset();
$r = http(18101, 'POST', '/api.php?action=update_now', ['cookie' => $sidNoTok, 'headers' => ['X-CSRF-Token' => '']]);
check('C1 a session that has no token yet cannot be satisfied by an empty header: 403, nothing started', $r['status'] === 403 && started() === 0, brief($r));

sudoReset();
$r = http(18101, 'POST', '/api.php?action=update_now', ['headers' => ['X-CSRF-Token' => $tok]]);
check('C1 localhost, no session cookie (the built-in-server bypass): update_now is NOT exempted - 403, nothing started',
    $r['status'] === 403 && started() === 0 && !anyUpdaterRun(), brief($r) . ' sudo.log: ' . sudoLog());
sudoReset();
$r = http(18101, 'POST', '/api.php?action=update_now');
check('C1 localhost, no cookie, no token: 403, nothing started', $r['status'] === 403 && started() === 0 && !anyUpdaterRun(), brief($r));

sudoReset();
$r = http(18101, 'GET', '/api.php?action=update_now', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok]]);
check('C1 GET update_now is still 405 (valid session and token) and starts nothing', $r['status'] === 405 && started() === 0 && !anyUpdaterRun(), brief($r));

sudoReset(1);
$r = http(18101, 'POST', '/api.php?action=update_now', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok]]);
check('C1 sudo refuses (exit 1): HTTP 500, success=false, no "Update started"',
    $r['status'] === 500 && ($r['json']['success'] ?? null) === false && strpos($r['raw'], 'Update started') === false, brief($r));
sudoReset(0);

// ============================================================================ C2: the bypass decision
$src = (string)@file_get_contents("$webDir/session_check.php");
$fn = null;
if (preg_match('/function irongate_local_bypass_allowed\(.*?\n}\n/s', $src, $m)) { $fn = $m[0]; }
check('C2 session_check.php has irongate_local_bypass_allowed(string $sapi, string $addr, bool $hasCookie): bool', $fn !== null
    && preg_match('/function irongate_local_bypass_allowed\(string \$sapi, string \$addr, bool \$hasCookie\): bool/', $fn) === 1);
if ($fn !== null) { eval($fn); }
$cases = [
    ['fpm-fcgi', '127.0.0.1', false, false], ['fpm-fcgi', '::1', false, false], ['fpm-fcgi', '127.0.0.1', true, false],
    ['cgi-fcgi', '127.0.0.1', false, false], ['apache2handler', '127.0.0.1', false, false], ['cli', '127.0.0.1', false, false],
    ['cli-server', '127.0.0.1', false, true], ['cli-server', '::1', false, true],
    ['cli-server', '127.0.0.1', true, false], ['cli-server', '192.168.1.5', false, false], ['cli-server', '', false, false],
    ['cli-server', '127.0.0.2', false, false], ['cli-server', '::ffff:127.0.0.1', false, false],
];
foreach ($cases as [$sapi, $addr, $cookie, $want]) {
    $got = ($fn !== null && function_exists('irongate_local_bypass_allowed')) ? irongate_local_bypass_allowed($sapi, $addr, $cookie) : 'no function';
    check(sprintf("C2 irongate_local_bypass_allowed('%s', '%s', %s) === %s", $sapi, $addr, $cookie ? 'true' : 'false', $want ? 'true' : 'false'), $got === $want, 'got ' . var_export($got, true));
}
check('C2 the guard passes the real PHP_SAPI to the decision', preg_match('/irongate_local_bypass_allowed\(PHP_SAPI,/', $src) === 1);

// ============================================================================ C2: the bypass, end to end
// control: the real built-in server keeps the bypass (this is how the other suites drive api.php)
$r = http(18101, 'GET', '/api.php?action=settings');
check('C2 control: under cli-server a loopback request without a cookie still reaches api.php (200)', $r['status'] === 200 && ($r['json']['success'] ?? null) === true, brief($r));

// the same files, with the guard told that it runs under php-fpm
$fpmok = false;
if (substr_count($src, 'PHP_SAPI') === 1) {
    foreach (glob("$webDir/*.php") as $f) { copy($f, "$work/fpmroot/" . basename($f)); }
    file_put_contents("$work/fpmroot/session_check.php", str_replace('PHP_SAPI', "'fpm-fcgi'", $src));
    $fpmok = startServer("$work/fpmroot", 18102, $env, $work);
}
check('C2 setup: a copy of web/ whose guard sees SAPI fpm-fcgi is served (PHP_SAPI occurs once in session_check.php)', $fpmok);
if ($fpmok) {
    $r = http(18102, 'GET', '/api.php?action=settings');
    check('C2 fpm-fcgi: loopback GET without a cookie is 401 auth_required (read endpoint)', $r['status'] === 401 && ($r['json']['error'] ?? '') === 'auth_required', brief($r));
    $r = http(18102, 'GET', '/api.php?action=update_log');
    check('C2 fpm-fcgi: loopback GET update_log without a cookie is 401', $r['status'] === 401, brief($r));
    $r = http(18102, 'POST', '/api.php?action=settings', ['body' => ['qa_probe' => 'planted']]);
    check('C2 fpm-fcgi: loopback state-changing POST without a cookie is 401 and nothing is stored',
        $r['status'] === 401 && dbq("SELECT COUNT(*) FROM settings WHERE key = 'qa_probe'") == 0, brief($r));
    sudoReset();
    $r = http(18102, 'POST', '/api.php?action=update_settings', ['body' => ['auto_update_enabled' => true]]);
    check('C2 fpm-fcgi: loopback POST update_settings without a cookie is 401 and sudo is not touched',
        $r['status'] === 401 && sudoLog() === '' && dbq("SELECT value FROM settings WHERE key = 'auto_update_enabled'") === 'false', brief($r) . ' sudo.log: ' . sudoLog());
    sudoReset();
    $r = http(18102, 'POST', '/api.php?action=update_now', ['headers' => ['X-CSRF-Token' => $tok]]);
    check('C2 fpm-fcgi: loopback POST update_now without a cookie is 401 and nothing is started', $r['status'] === 401 && started() === 0 && !anyUpdaterRun(), brief($r));
    $r = http(18102, 'GET', '/api.php?action=settings', ['cookie' => $sid]);
    check('C2 fpm-fcgi control: a real session still works (200)', $r['status'] === 200 && ($r['json']['success'] ?? null) === true, brief($r));
    sudoReset();
    $r = http(18102, 'POST', '/api.php?action=update_now', ['cookie' => $sid, 'headers' => ['X-CSRF-Token' => $tok]]);
    check('C2 fpm-fcgi control: session + token start the update through the one sudo rule', $r['status'] === 200 && started() === 1 && !anyUpdaterRun(), brief($r));
    sudoReset();
    $r = http(18102, 'POST', '/api.php?action=update_now', ['cookie' => $sid]);
    check('C2 fpm-fcgi: session without the token is 403, nothing started', $r['status'] === 403 && started() === 0, brief($r));
}

// ============================================================================ C1: the page hands the token over
$r = http(18101, 'GET', '/index.php', ['cookie' => $sid]);
check('C1 index.php (valid session) carries its CSRF token in a meta tag',
    $r['status'] === 200 && strpos($r['raw'], '<meta name="csrf-token" content="' . $tok . '">') !== false, brief($r));
check('C1 the dashboard\'s api() helper sends it as X-CSRF-Token', strpos($r['raw'], "'X-CSRF-Token'") !== false && strpos($r['raw'], 'meta[name="csrf-token"]') !== false);
check('C1 the Update now button goes through that helper (api(\'update_now\', {method:\'POST\'}))', strpos($r['raw'], "api('update_now', {method:'POST'})") !== false);

$sidOld = mkSession(['authenticated' => true, 'username' => 'admin', 'last_activity' => time()]);   // a session from before the token existed
$r = http(18101, 'GET', '/index.php', ['cookie' => $sidOld]);
preg_match('#<meta name="csrf-token" content="([0-9a-f]{64})">#', $r['raw'], $mm);
$stored = (string)@file_get_contents("$work/sess/sess_$sidOld");
check('C1 a session that predates the token is given one (64 hex), shown in the page and stored in the session',
    $r['status'] === 200 && isset($mm[1]) && strpos($stored, $mm[1]) !== false, brief($r) . ' stored=' . $stored);

$r = http(18101, 'GET', '/index.php');
check('C1 an anonymous visitor gets a redirect to the login page, no page and no token',
    $r['status'] === 302 && preg_match('#csrf-token#', $r['raw']) === 0, brief($r));

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
