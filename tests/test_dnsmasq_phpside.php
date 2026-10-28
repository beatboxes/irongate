<?php
/**
 * irongate-audit O4: the web side of the dnsmasq redesign.
 *
 * Drives the real web/api.php end to end over HTTP against a scratch SQLite database, with a recording stand-in
 * for the root helper (/opt/irongate/dnsmasq-apply) and for sudo. It checks
 *   - api.php itself never writes /etc/dnsmasq.conf or /etc/dnsmasq.d/* (the files are root's; the sentinel
 *     files below must come out byte-identical, also for a crafted domain "local\ndhcp-script=/tmp/x");
 *   - what api.php stages for the helper: an allow-listed request, nothing else from the database;
 *   - that the JSON the dashboard gets back is the same as before for success, validation failure, start failure;
 *   - characterization: for ten settings vectors, the request api.php stages is written to $IG_OUT together
 *     with what the OLD generator of 18e5177 (tests/fixtures/legacy_dnsmasq_18e5177.php) produced for the same
 *     database; tests/test_dnsmasq_apply.py then proves the root helper renders the same files from the request.
 *
 * It overwrites /var/www/irongate, /etc/dnsmasq.conf and /opt/irongate, so it refuses to run outside a throw-away
 * container:
 *
 *   docker run --rm --network none -e IRONGATE_TEST_SANDBOX=1 -e IG_OUT=/out -v "$PWD":/w:ro -v <out>:/out \
 *       -w /w php:8.3-cli php tests/test_dnsmasq_phpside.php _work/patched/web
 *
 * Exit status 0 = every case passed. Against the web/ of 18e5177 it fails (that code writes the files itself).
 */

if (PHP_SAPI !== 'cli') { exit(1); }
if (getenv('IRONGATE_TEST_SANDBOX') !== '1') {
    fwrite(STDERR, "refusing to run: set IRONGATE_TEST_SANDBOX=1 inside a disposable container\n");
    exit(2);
}
$webDir = realpath($argv[1] ?? 'web');
$docroot = '/var/www/irongate';
$out = getenv('IG_OUT') ?: '';
if ($webDir === false || !is_file("$webDir/api.php")) { fwrite(STDERR, "usage: php test_dnsmasq_phpside.php <web-dir>\n"); exit(2); }
foreach ([$docroot . '/dhcp.db', '/etc/dnsmasq.conf', '/opt/irongate', '/var/lib/irongate'] as $p) {
    if (file_exists($p)) { fwrite(STDERR, "refusing to run: $p already exists\n"); exit(2); }
}

@mkdir($docroot, 0777, true);
foreach (glob("$webDir/*.php") as $f) { copy($f, "$docroot/" . basename($f)); }

// ---- stand-ins -------------------------------------------------------------------------------------------------
$stage = '/var/lib/irongate/dnsmasq-staged';
@mkdir($stage, 0777, true);
@mkdir('/opt/irongate', 0755, true);
@mkdir('/etc/dnsmasq.d', 0755, true);
@mkdir('/tmp/captured', 0777, true);
function put($path, $text, $mode = 0644) { file_put_contents($path, $text); chmod($path, $mode); }
put('/usr/local/bin/sudo', "#!/bin/sh\n[ \"\$1\" = \"-n\" ] && shift\necho \"sudo \$*\" >> /tmp/sudo.log\nexec \"\$@\"\n", 0755);
// what the OLD code ran by name: a dnsmasq that likes everything, systemctl, journalctl
put('/usr/local/bin/dnsmasq', "#!/bin/sh\necho 'dnsmasq: syntax check OK.' >&2\nexit 0\n", 0755);
put('/usr/local/bin/systemctl', "#!/bin/sh\necho \"systemctl \$*\" >> /tmp/systemctl.log\nexit 0\n", 0755);
put('/usr/local/bin/journalctl', "#!/bin/sh\necho 'journal: simulated line'\n", 0755);
// the root helper: copies the staged request (so the test can read it), consumes it like the real one, answers per mode
put('/opt/irongate/dnsmasq-apply', <<<'BASH'
#!/bin/bash
S=/var/lib/irongate/dnsmasq-staged
n=$(ls /tmp/captured | wc -l)
if ! cp "$S/request.json" "/tmp/captured/$(printf %03d $n).json" 2>/dev/null; then
    echo '{"success": false, "stage": "validation", "error": "Request refused: no staged request"}'; exit 2
fi
rm -f "$S/request.json"
case "$(cat /tmp/fake-helper.mode 2>/dev/null || echo ok)" in
  ok) echo '{"success": true, "stage": "start"}' ;;
  validate) echo '{"success": true, "stage": "validation", "valid": true, "output": "dnsmasq: syntax check OK.", "return_code": 0}' ;;
  invalid) echo '{"success": true, "stage": "validation", "valid": false, "output": "dnsmasq: bad IP address at line 3", "return_code": 1}' ;;
  refuse) echo '{"success": false, "stage": "validation", "error": "Request refused: invalid domain"}'; exit 2 ;;
  testfail) echo '{"success": false, "stage": "validation", "error": "dnsmasq: bad IP address at line 9 of /etc/x", "output": "x"}'; exit 3 ;;
  startfail) echo '{"success": false, "stage": "start", "error": "Service start failed", "output": "Job for dnsmasq.service failed", "restored": true}'; exit 4 ;;
  garbage) echo 'Traceback (most recent call last): boom' ;;
esac
BASH, 0755);
function mode($m) { file_put_contents('/tmp/fake-helper.mode', $m); }
function captured() { $f = glob('/tmp/captured/*.json'); sort($f); return $f; }
function lastRequest() { $f = captured(); return $f ? json_decode(file_get_contents(end($f)), true) : null; }
function sorted($a) { if (is_array($a)) { ksort($a); } return $a; }

// ---- server ----------------------------------------------------------------------------------------------------
$port = 18098;
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
        INSERT INTO settings VALUES ('irongate_enabled','false'), ('blockchain_network','preprod'), ('installed_commit','abc1234'), ('auto_update_enabled','false');");
    $db->close();
    chmod($path, 0666);
}

function call($method, $action, $body = null, $query = '') {
    global $port;
    $ctx = stream_context_create(['http' => [
        'method' => $method, 'ignore_errors' => true, 'timeout' => 30,
        'header' => "Content-Type: application/json\r\n",
        'content' => $body === null ? '' : json_encode($body)]]);
    $raw = (string)@file_get_contents("http://127.0.0.1:$port/api.php?action=" . urlencode($action) . $query, false, $ctx);
    $hdrs = $http_response_header ?? [];
    preg_match('#^HTTP/\S+\s+(\d{3})#', $hdrs[0] ?? '', $m);
    return ['status' => (int)($m[1] ?? 0), 'json' => json_decode($raw, true), 'raw' => $raw];
}

function dbx($sql) { global $docroot; $db = new SQLite3("$docroot/dhcp.db"); $db->exec($sql); $db->close(); }

$pass = 0; $fail = 0;
function check($name, $cond, $detail = '') {
    global $pass, $fail;
    if ($cond) { $pass++; echo "PASS  $name\n"; }
    else { $fail++; echo "FAIL  $name" . ($detail !== '' ? "  -- $detail" : '') . "\n"; }
}
function brief($r) { return 'status=' . $r['status'] . ' body=' . substr(trim($r['raw']), 0, 240); }

const SENT_MAIN = "# SENTINEL main: only the root helper may change this file\n";
const SENT_RES = "# SENTINEL reservations: only the root helper may change this file\n";
function sentinels() { file_put_contents('/etc/dnsmasq.conf', SENT_MAIN); file_put_contents('/etc/dnsmasq.d/reservations.conf', SENT_RES); }
function sentinelsIntact() {
    return @file_get_contents('/etc/dnsmasq.conf') === SENT_MAIN && @file_get_contents('/etc/dnsmasq.d/reservations.conf') === SENT_RES
        && array_values(array_diff(scandir('/etc/dnsmasq.d'), ['.', '..'])) === ['reservations.conf'];
}
function resetCaptured() { foreach (glob('/tmp/captured/*') as $f) { unlink($f); } @unlink('/tmp/systemctl.log'); }

$GOOD = ['dhcp_enabled' => 'true', 'interface' => 'eth0', 'cidr' => '24', 'range_start' => '192.168.1.100', 'range_end' => '192.168.1.200',
         'gateway' => '192.168.1.1', 'dns_primary' => '8.8.8.8', 'dns_secondary' => '1.1.1.1', 'lease_time' => '24h', 'domain' => 'local'];
$KEYS = array_keys($GOOD);

makeDb("$docroot/dhcp.db");
sentinels();
mode('ok');

// ---- A: api.php never writes the root's files --------------------------------------------------------------------
$evil = "local\ndhcp-script=/tmp/x";
$r = call('POST', 'settings', array_merge($GOOD, ['domain' => $evil]));
check('O4 a crafted domain ("\\ndhcp-script=/tmp/x") through the settings endpoint leaves /etc/dnsmasq.conf and /etc/dnsmasq.d byte-identical', sentinelsIntact(),
    'main now: ' . substr((string)@file_get_contents('/etc/dnsmasq.conf'), 0, 160));
check('O4 ... and no dhcp-script=/tmp/x line exists in any dnsmasq file', strpos((string)@file_get_contents('/etc/dnsmasq.conf'), '/tmp/x') === false
    && strpos((string)@file_get_contents('/etc/dnsmasq.d/reservations.conf'), '/tmp/x') === false);
$r = call('POST', 'settings', array_merge($GOOD, ['dhcp-script' => '/tmp/x']));
check('O4 a "dhcp-script" settings key stored through the generic endpoint is not written to the config either', sentinelsIntact());
$r = call('POST', 'reservations', ['mac' => 'aa:bb:cc:dd:ee:01', 'ip' => '192.168.1.10', 'hostname' => 'a']);
check('O4 adding a reservation does not write /etc/dnsmasq.d/reservations.conf from the web tier', sentinelsIntact());
$db = new SQLite3("$docroot/dhcp.db"); $id = $db->querySingle("SELECT id FROM reservations LIMIT 1"); $db->close();
$r = call('DELETE', 'reservations', null, '&id=' . (int)$id);
check('O4 deleting a reservation does not write /etc/dnsmasq.d/reservations.conf from the web tier', sentinelsIntact());
$r = call('GET', 'apply');
check('O4 the apply action does not write the files either', sentinelsIntact());

// ---- B: what is staged ------------------------------------------------------------------------------------------
makeDb("$docroot/dhcp.db"); sentinels(); resetCaptured(); mode('ok');
dbx("INSERT INTO settings VALUES ('update_token_hint','secret-ish'), ('irongate_bridge_ip','10.99.0.1')");
$r = call('POST', 'settings', array_merge($GOOD, ['domain' => $evil]));
$req = lastRequest();
check('O4 api.php stages a request for the helper (request.json is read by the helper)', is_array($req), 'captured: ' . count(captured()));
check('O4 the request is versioned and names the action', ($req['version'] ?? null) === 1 && ($req['action'] ?? null) === 'apply', json_encode($req));
check('O4 settings is a JSON object that holds only allow-listed keys and no other row of the database',
    is_array($req) && is_array($req['settings'] ?? null) && array_diff(array_keys($req['settings']), $KEYS) === [] && !isset($req['settings']['installed_commit']), json_encode($req['settings'] ?? null));
check('O4 the crafted domain reaches the helper unchanged: the helper, not api.php, is the validator', ($req['settings']['domain'] ?? null) === $evil);
check('O4 reservations is a list', is_array($req) && array_is_list($req['reservations'] ?? null));
check('O4 the request file is consumed and no temp file is left in the staging directory',
    array_values(array_diff(scandir($stage), ['.', '..', '.lock'])) === [], json_encode(scandir($stage)));
check('O4 the helper is run through sudo with no arguments', (string)@file_get_contents('/tmp/sudo.log') !== '' && preg_match('#^sudo /opt/irongate/dnsmasq-apply$#m', (string)@file_get_contents('/tmp/sudo.log')) === 1,
    (string)@file_get_contents('/tmp/sudo.log'));

// DHCP off: nothing but the switch and the interface is sent
resetCaptured();
$r = call('POST', 'settings', array_merge($GOOD, ['dhcp_enabled' => 'false', 'domain' => $evil, 'gateway' => 'junk']));
$req = lastRequest();
check('O4 DHCP off: only dhcp_enabled=false and the interface are staged (unused values stay home)', sorted($req['settings'] ?? null) === ['dhcp_enabled' => 'false', 'interface' => 'eth0'], json_encode($req['settings'] ?? null));
resetCaptured();
$r = call('POST', 'settings', array_merge($GOOD, ['range_end' => '']));
$req = lastRequest();
check('O4 DHCP on but range incomplete: staged as off (the old generator printed the "DHCP is disabled" branch)', sorted($req['settings'] ?? null) === ['dhcp_enabled' => 'false', 'interface' => 'eth0'], json_encode($req['settings'] ?? null));
resetCaptured();
$r = call('POST', 'settings', array_merge($GOOD, ['interface' => '']));
$req = lastRequest();
check('O4 empty interface is not staged (the helper looks up the default route, as the old generator did)', is_array($req) && !array_key_exists('interface', $req['settings']), json_encode($req['settings'] ?? null));

// reservations: hostnames sanitised as before, database order, all rows
makeDb("$docroot/dhcp.db"); resetCaptured();
call('POST', 'settings', $GOOD);
call('POST', 'reservations', ['mac' => 'AA:BB:CC:DD:EE:01', 'ip' => '192.168.1.10', 'hostname' => 'My Laptop']);
call('POST', 'reservations', ['mac' => 'aa:bb:cc:dd:ee:02', 'ip' => '192.168.1.11', 'hostname' => 'cam_01!']);
call('POST', 'reservations', ['mac' => 'aa:bb:cc:dd:ee:03', 'ip' => '192.168.1.12']);
$req = lastRequest();
check('O4 reservations are staged in database order, mac lower-cased by addReservation, hostnames sanitised like before',
    ($req['reservations'] ?? null) === [['mac' => 'aa:bb:cc:dd:ee:01', 'ip' => '192.168.1.10', 'hostname' => 'My-Laptop'],
        ['mac' => 'aa:bb:cc:dd:ee:02', 'ip' => '192.168.1.11', 'hostname' => 'cam01'],
        ['mac' => 'aa:bb:cc:dd:ee:03', 'ip' => '192.168.1.12', 'hostname' => '']], json_encode($req['reservations'] ?? null));

// a row that did not come through addReservation() (older database, direct write) is sanitised when it is staged
makeDb("$docroot/dhcp.db"); resetCaptured();
dbx("INSERT INTO reservations (mac, ip, hostname) VALUES ('aa:bb:cc:dd:ee:77', '192.168.1.77', 'Bad Host!\ndhcp-script=/tmp/x')");
call('POST', 'settings', $GOOD);
$req = lastRequest();
check('O4 a hostname stored unsanitised in the database is sanitised again when it is staged (the old file writer did the same)',
    ($req['reservations'][0]['hostname'] ?? null) === 'Bad-Hostdhcp-scripttmpx', json_encode($req['reservations'] ?? null));

// F5: white space around a value (dnsmasq ignores it, the old generator wrote it as it was) is removed before the request is staged
makeDb("$docroot/dhcp.db"); resetCaptured(); mode('ok');
call('POST', 'settings', array_merge($GOOD, ['gateway' => '192.168.1.1 ', 'range_start' => ' 192.168.1.100', 'domain' => 'local ', 'dns_primary' => "\t8.8.8.8\n", 'interface' => ' eth0 ']));
dbx("INSERT INTO reservations (mac, ip, hostname) VALUES (' aa:bb:cc:dd:ee:55 ', '192.168.1.55 ', 'h')");
call('POST', 'settings', array_merge($GOOD, ['gateway' => '192.168.1.1 ', 'range_start' => ' 192.168.1.100', 'domain' => 'local ', 'dns_primary' => "\t8.8.8.8\n", 'interface' => ' eth0 ']));
$req = lastRequest();
check('F5 stray white space around setting values is trimmed before staging',
    ($req['settings']['gateway'] ?? null) === '192.168.1.1' && ($req['settings']['range_start'] ?? null) === '192.168.1.100' && ($req['settings']['domain'] ?? null) === 'local'
    && ($req['settings']['dns_primary'] ?? null) === '8.8.8.8' && ($req['settings']['interface'] ?? null) === 'eth0', json_encode($req['settings'] ?? null));
check('F5 ... and around the mac and ip of a reservation row', ($req['reservations'][0]['mac'] ?? null) === 'aa:bb:cc:dd:ee:55' && ($req['reservations'][0]['ip'] ?? null) === '192.168.1.55', json_encode($req['reservations'] ?? null));
resetCaptured();
call('POST', 'settings', array_merge($GOOD, ['domain' => "lo\ncal"]));
check('F5 an inner newline is not touched by the trim (the helper refuses it)', (lastRequest()['settings']['domain'] ?? null) === "lo\ncal");

// F10: a directory named request.json blocks every later rename; api.php removes an empty one and reports a full one cleanly
makeDb("$docroot/dhcp.db"); resetCaptured(); mode('ok');
mkdir("$stage/request.json");
$r = call('POST', 'settings', $GOOD);
check('F10 an empty directory named request.json is removed and the request goes through', ($r['json']['success'] ?? null) === true && !is_dir("$stage/request.json") && is_array(lastRequest()), brief($r));
mkdir("$stage/request.json"); file_put_contents("$stage/request.json/x", 'junk');
$r = call('POST', 'settings', $GOOD);
check('F10 a directory with content in the way is a clean JSON failure, not a PHP error', ($r['json']['success'] ?? null) === false && ($r['json']['stage'] ?? '') === 'validation'
    && strpos($r['json']['error'] ?? '', 'could not be staged') !== false, brief($r));
unlink("$stage/request.json/x"); rmdir("$stage/request.json");

// ---- C: the dashboard's answers are unchanged ---------------------------------------------------------------------
makeDb("$docroot/dhcp.db"); sentinels(); resetCaptured();
mode('ok');
$r = call('POST', 'settings', $GOOD);
check('C settings POST, helper ok: {"success":true}', $r['status'] === 200 && $r['json'] === ['success' => true], brief($r));
$r = call('GET', 'apply');
check('C apply, helper ok: {"success":true}', $r['json'] === ['success' => true], brief($r));
$r = call('POST', 'reservations', ['mac' => 'aa:bb:cc:dd:ee:09', 'ip' => '192.168.1.19', 'hostname' => 'z']);
check('C reservation add, helper ok: success + applied.success', ($r['json']['success'] ?? null) === true && ($r['json']['applied']['success'] ?? null) === true, brief($r));
mode('refuse');
$r = call('POST', 'settings', $GOOD);
check('C helper refuses: success=false, error "Config validation failed: ...", stage validation',
    ($r['json']['success'] ?? null) === false && ($r['json']['stage'] ?? '') === 'validation' && ($r['json']['error'] ?? '') === 'Config validation failed: Request refused: invalid domain', brief($r));
mode('testfail');
$r = call('POST', 'settings', $GOOD);
check('C dnsmasq --test fails: the old "Config validation failed: <dnsmasq output>" message and stage', ($r['json']['error'] ?? '') === 'Config validation failed: dnsmasq: bad IP address at line 9 of /etc/x' && ($r['json']['stage'] ?? '') === 'validation', brief($r));
mode('startfail');
$r = call('POST', 'settings', $GOOD);
check('C start fails: success=false, error "Service start failed", output, journal, stage start',
    ($r['json']['success'] ?? null) === false && ($r['json']['error'] ?? '') === 'Service start failed' && ($r['json']['output'] ?? '') === 'Job for dnsmasq.service failed'
    && strpos($r['json']['journal'] ?? '', 'journal: simulated line') !== false && ($r['json']['stage'] ?? '') === 'start', brief($r));
mode('garbage');
$r = call('POST', 'settings', $GOOD);
check('C helper gives no usable answer: a clean JSON failure, not a PHP error', ($r['json']['success'] ?? null) === false && ($r['json']['stage'] ?? '') === 'validation'
    && strpos($r['json']['error'] ?? '', 'Config validation failed: dnsmasq-apply gave no answer') === 0, brief($r));
mode('validate');
$r = call('GET', 'validate');
check('C validate: {"success":true,"data":{"valid":true,"output":...,"return_code":0}}', $r['json'] === ['success' => true, 'data' => ['valid' => true, 'output' => 'dnsmasq: syntax check OK.', 'return_code' => 0]], brief($r));
check('C validate stages a request with action validate', (lastRequest()['action'] ?? '') === 'validate');
mode('invalid');
$r = call('GET', 'validate');
check('C validate, dnsmasq unhappy: valid=false with its output', ($r['json']['data']['valid'] ?? null) === false && ($r['json']['data']['output'] ?? '') === 'dnsmasq: bad IP address at line 3' && ($r['json']['data']['return_code'] ?? null) === 1, brief($r));
mode('ok');
// the staging directory is gone: a JSON failure, the files stay alone
$hold = $stage . '.hold'; rename($stage, $hold);
$r = call('POST', 'settings', $GOOD);
check('C no staging directory: clean JSON failure and the sentinels are untouched', ($r['json']['success'] ?? null) === false && ($r['json']['stage'] ?? '') === 'validation' && sentinelsIntact(), brief($r));
rename($hold, $stage);
// restart/stop/start actions are unchanged (they never touched the files)
$r = call('GET', 'restart');
check('C restart still goes through sudo systemctl (unchanged)', ($r['json']['success'] ?? null) === true, brief($r));

// ---- D: characterization against the old generator -----------------------------------------------------------------
$legacy = file_get_contents(__DIR__ . '/fixtures/legacy_dnsmasq_18e5177.php');
$vectors = [
    '01-live-like'      => [$GOOD, [['aa:bb:cc:dd:ee:01', '192.168.1.10', 'printer'], ['aa:bb:cc:dd:ee:02', '192.168.1.11', 'My Laptop'], ['aa:bb:cc:dd:ee:03', '192.168.1.12', '']]],
    '02-disabled'       => [array_merge($GOOD, ['dhcp_enabled' => 'false']), []],
    '03-no-gw-one-dns'  => [array_merge($GOOD, ['gateway' => '', 'dns_secondary' => '', 'domain' => '']), [['aa:bb:cc:dd:ee:01', '192.168.1.10', 'a']]],
    '04-infinite'       => [array_merge($GOOD, ['lease_time' => 'infinite']), []],
    '05-seconds-cidr16' => [array_merge($GOOD, ['lease_time' => '3600', 'cidr' => '16', 'range_start' => '10.1.0.10', 'range_end' => '10.1.9.250', 'gateway' => '10.1.0.1']), []],
    '06-range-end-empty' => [array_merge($GOOD, ['range_end' => '']), [['aa:bb:cc:dd:ee:01', '192.168.1.10', 'a']]],
    '07-vlan-iface-28'  => [array_merge($GOOD, ['interface' => 'wlan0.100', 'cidr' => '28', 'range_start' => '172.16.0.2', 'range_end' => '172.16.0.14', 'gateway' => '172.16.0.1']), []],
    '08-secondary-only' => [array_merge($GOOD, ['dns_primary' => '']), []],
    '09-reservations-only' => [['dhcp_enabled' => 'false', 'interface' => 'enp3s0'], [['aa:bb:cc:dd:ee:01', '192.168.1.10', 'x-1'], ['aa:bb:cc:dd:ee:02', '192.168.1.11', 'Cam_01']]],
    '10-upper-lease'    => [array_merge($GOOD, ['lease_time' => '12H', 'cidr' => '20']), [['AA:BB:CC:DD:EE:0F', '192.168.1.15', '']]],
    // round 5b: more live-plausible values (end0, a bridge, 7d/30m/1w leases, /8 /32 /0, mixed-case domain, many reservations, ...)
    'x01-end0-24h'      => [array_merge($GOOD, ['interface' => 'end0', 'range_start' => '192.168.0.50', 'range_end' => '192.168.0.250', 'gateway' => '192.168.0.1', 'domain' => '']), [['aa:bb:cc:dd:ee:01', '192.168.0.10', 'NAS'], ['aa:bb:cc:dd:ee:02', '192.168.0.11', 'tv-livingroom']]],
    'x02-br-lan-1w'     => [array_merge($GOOD, ['interface' => 'br-lan', 'lease_time' => '1w']), []],
    'x03-7d'            => [array_merge($GOOD, ['lease_time' => '7d', 'domain' => 'home.arpa']), []],
    'x04-30m'           => [array_merge($GOOD, ['lease_time' => '30m']), []],
    'x05-cidr8'         => [array_merge($GOOD, ['cidr' => '8', 'range_start' => '10.0.0.100', 'range_end' => '10.0.0.200', 'gateway' => '10.0.0.1']), []],
    'x06-cidr32'        => [array_merge($GOOD, ['cidr' => '32']), []],
    'x07-cidr0'         => [array_merge($GOOD, ['cidr' => '0']), []],
    'x08-domain-mixed'  => [array_merge($GOOD, ['domain' => 'Example.Com']), []],
    'x09-no-dns'        => [array_merge($GOOD, ['dns_primary' => '', 'dns_secondary' => '']), []],
    'x10-hostnames'     => [$GOOD, [['AA:BB:CC:DD:EE:01', '192.168.1.20', 'Living Room TV'], ['aa:bb:cc:dd:ee:02', '192.168.1.21', 'cam.01'], ['aa:bb:cc:dd:ee:03', '192.168.1.22', '  spaced  out  '], ['aa:bb:cc:dd:ee:04', '192.168.1.23', 'UPPER-lower-123'], ['aa:bb:cc:dd:ee:05', '192.168.1.24', str_repeat('a', 63)]]],
    'x11-many-res'      => [$GOOD, array_map(function ($i) { return [sprintf('aa:bb:cc:00:%02x:%02x', intdiv($i, 256), $i % 256), '192.168.1.' . (10 + $i % 90), 'h' . $i]; }, range(1, 60))],
    'x12-infinite-upper' => [array_merge($GOOD, ['lease_time' => 'INFINITE']), []],
    'x13-vlan'          => [array_merge($GOOD, ['interface' => 'enp3s0.20']), []],
    'x14-dhcp-off-res'  => [array_merge($GOOD, ['dhcp_enabled' => 'false']), [['aa:bb:cc:dd:ee:01', '192.168.1.10', 'x']]],
    'x15-gw-only'       => [array_merge($GOOD, ['dns_primary' => '', 'dns_secondary' => '', 'domain' => '']), []],
    'x16-empty-cidr'    => [array_merge($GOOD, ['cidr' => '']), []],
    'x17-empty-lease'   => [array_merge($GOOD, ['lease_time' => '']), []],
    'x18-ws-gateway'    => [array_merge($GOOD, ['gateway' => '192.168.1.1 ']), []],
    'x19-ws-start'      => [array_merge($GOOD, ['range_start' => ' 192.168.1.100']), []],
    'x20-domain-trailing-space' => [array_merge($GOOD, ['domain' => 'local ']), []],
];
foreach ($vectors as $name => [$settings, $res]) {
    makeDb("$docroot/dhcp.db"); resetCaptured(); mode('ok');
    $r = call('POST', 'settings', $settings);
    foreach ($res as [$mac, $ip, $host]) {
        call('POST', 'reservations', ['mac' => $mac, 'ip' => $ip, 'hostname' => $host]);
    }
    $req = lastRequest();
    if (!is_array($req)) {   // api.php refused the save itself (an empty lease time): nothing is staged, nothing to compare
        check("D $name: api.php refused the save before anything was staged (x17: an empty lease time)", $name === 'x17-empty-lease', json_encode($req));
        continue;
    }
    check("D $name: api.php staged a request", is_array($req));
    // what the OLD generator makes of the same database
    $dbl = new SQLite3("$docroot/dhcp.db");
    $oldMain = $oldRes = null;
    if (!function_exists('legacyGenerate')) {
        eval('?>' . str_replace('/etc/dnsmasq.d/reservations.conf', '/tmp/legacy-reservations.out', $legacy));
        function legacyGenerate($db) { return generateDnsmasqConfig($db); }
    }
    @unlink('/tmp/legacy-reservations.out');
    $oldMain = legacyGenerate($dbl);
    syncReservationsToFile($dbl);
    $oldRes = (string)@file_get_contents('/tmp/legacy-reservations.out');
    $dbl->close();
    check("D $name: the old generator's output was produced", strpos($oldMain, 'dhcp-script=/opt/irongate/dhcp-notify.sh') !== false && $oldRes !== '');
    if ($out !== '' && is_array($req)) {
        file_put_contents("$out/$name.request.json", json_encode($req));
        file_put_contents("$out/$name.legacy.conf", $oldMain);
        file_put_contents("$out/$name.legacy.res", $oldRes);
    }
}

echo "\n$pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
