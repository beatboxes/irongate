<?php
/**
 * Irongate WebUI Login
 * Validates credentials against /etc/irongate/auth.json (bcrypt).
 * Rate limiting: 5 failed attempts within 15 minutes -> 15 minute lockout.
 */
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
session_start();

$AUTH_FILE = '/etc/irongate/auth.json';
$MAX_ATTEMPTS = 5;
$WINDOW_SECONDS = 15 * 60;
$LOCKOUT_SECONDS = 15 * 60;

if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    header('Location: /');
    exit;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function loadAuth($file) {
    $auth = json_decode(@file_get_contents($file), true);
    return is_array($auth) ? $auth : null;
}

function saveAuth($file, $auth) {
    return @file_put_contents($file, json_encode($auth, JSON_PRETTY_PRINT) . "\n", LOCK_EX) !== false;
}

function safeRedirectTarget() {
    $r = $_POST['redirect'] ?? $_GET['redirect'] ?? '/';
    // Same-origin relative paths only: must start with a single '/'
    if (!is_string($r) || $r === '' || $r[0] !== '/' || (isset($r[1]) && $r[1] === '/')) {
        return '/';
    }
    return $r;
}

$error = '';
$notice = '';
if (isset($_GET['expired'])) {
    $notice = 'Session expired — please sign in again.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], (string)$csrf)) {
        $error = 'Invalid session token — please reload the page and try again.';
    } else {
        $auth = loadAuth($AUTH_FILE);
        if (!$auth || empty($auth['password_hash']) || empty($auth['username'])) {
            $error = 'Authentication is not configured correctly.';
        } else {
            $now = time();
            $lockedUntil = intval($auth['locked_until'] ?? 0);
            if ($lockedUntil > $now) {
                $mins = (int)ceil(($lockedUntil - $now) / 60);
                $error = 'Too many failed attempts. Try again in ' . $mins . ' minute' . ($mins === 1 ? '' : 's') . '.';
            } else {
                $user = (string)($_POST['username'] ?? '');
                $pass = (string)($_POST['password'] ?? '');
                if ($user === $auth['username'] && password_verify($pass, $auth['password_hash'])) {
                    $auth['failed_attempts'] = 0;
                    $auth['first_failed_at'] = 0;
                    $auth['locked_until'] = 0;
                    saveAuth($AUTH_FILE, $auth);
                    session_regenerate_id(true);
                    $_SESSION['authenticated'] = true;
                    $_SESSION['username'] = $auth['username'];
                    $_SESSION['last_activity'] = time();
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    header('Location: ' . safeRedirectTarget());
                    exit;
                }
                // Failed attempt — rolling window
                $first = intval($auth['first_failed_at'] ?? 0);
                if ($first === 0 || ($now - $first) > $WINDOW_SECONDS) {
                    $auth['failed_attempts'] = 1;
                    $auth['first_failed_at'] = $now;
                } else {
                    $auth['failed_attempts'] = intval($auth['failed_attempts'] ?? 0) + 1;
                }
                if (intval($auth['failed_attempts']) >= $MAX_ATTEMPTS) {
                    $auth['locked_until'] = $now + $LOCKOUT_SECONDS;
                    $auth['failed_attempts'] = 0;
                    $auth['first_failed_at'] = 0;
                    $error = 'Too many failed attempts. Locked for 15 minutes.';
                } else {
                    $error = 'Invalid username or password.';
                }
                saveAuth($AUTH_FILE, $auth);
            }
        }
    }
}
$redirectValue = safeRedirectTarget();
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Irongate — Sign In</title>
    <style>
        :root{--bg:#1a1a2e;--surface:#16213e;--surface2:#0f3460;--primary:#e94560;--success:#00bf63;--warning:#ffc107;--danger:#dc3545;--text:#eee;--text-secondary:#aaa;}
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;}
        .login-card{background:var(--surface);border-radius:12px;padding:35px;width:100%;max-width:380px;box-shadow:0 8px 24px rgba(0,0,0,0.4);}
        .logo{display:flex;align-items:center;justify-content:center;gap:10px;font-size:1.4em;font-weight:bold;color:#e94560;margin-bottom:25px;letter-spacing:2px;}
        .logo svg{width:32px;height:32px;}
        .form-group{margin-bottom:15px;}
        .form-group label{display:block;margin-bottom:5px;color:var(--text-secondary);}
        .form-control{width:100%;padding:10px;border:1px solid var(--surface2);border-radius:6px;background:var(--bg);color:var(--text);font-size:1em;}
        .form-control:focus{outline:none;border-color:var(--primary);}
        .btn{display:block;width:100%;padding:12px;border:none;border-radius:6px;cursor:pointer;font-size:1em;background:var(--primary);color:white;margin-top:20px;}
        .btn:hover{opacity:0.9;}
        .alert{padding:12px;border-radius:8px;margin-bottom:15px;font-size:0.9em;}
        .alert-danger{background:rgba(220,53,69,0.2);border:1px solid var(--danger);}
        .alert-warning{background:rgba(255,193,7,0.2);border:1px solid var(--warning);}
        .subtitle{text-align:center;color:var(--text-secondary);font-size:0.85em;margin-bottom:20px;}
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo">
            <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,5A3,3 0 0,1 15,8A3,3 0 0,1 12,11A3,3 0 0,1 9,8A3,3 0 0,1 12,5M17.13,17C15.92,18.85 14.11,20.24 12,20.92C9.89,20.24 8.08,18.85 6.87,17C6.53,16.5 6.24,16 6,15.47C6,13.82 8.71,12.47 12,12.47C15.29,12.47 18,13.79 18,15.47C17.76,16 17.47,16.5 17.13,17Z"/></svg>
            IRONGATE
        </div>
        <div class="subtitle">Sign in to manage your network</div>
        <?php if ($error !== ''): ?>
        <div class="alert alert-danger"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php elseif ($notice !== ''): ?>
        <div class="alert alert-warning"><?php echo htmlspecialchars($notice, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        <form method="POST" action="/login.php" autocomplete="on">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($redirectValue, ENT_QUOTES, 'UTF-8'); ?>">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" class="form-control" autocomplete="username" autofocus required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" class="form-control" autocomplete="current-password" required>
            </div>
            <button type="submit" class="btn">🔐 Sign In</button>
        </form>
    </div>
</body>
</html>
