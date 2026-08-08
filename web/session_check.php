<?php
/**
 * Irongate WebUI Session Guard
 * Include at the top of every protected page.
 *
 * - Browser pages: unauthenticated -> redirect to /login.php
 * - api.php: unauthenticated -> 401 JSON (the SPA fetch() helper handles the
 *   redirect; a 302-to-HTML would corrupt every frontend JSON error path)
 * - Local service bypass: requests from 127.0.0.1/::1 to api.php that carry
 *   no session cookie are exempted (defensive: no current local callers).
 */

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
    session_start();
}

$IRONGATE_SESSION_TIMEOUT = 4 * 60 * 60; // 4 hours of inactivity

$isApi = basename($_SERVER['SCRIPT_NAME'] ?? '') === 'api.php';

// Local service-to-service API bypass (no session cookie presented)
if ($isApi
    && in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)
    && !isset($_COOKIE[session_name()])) {
    return;
}

$authed = isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
$expired = false;

if ($authed && isset($_SESSION['last_activity'])
    && (time() - $_SESSION['last_activity'] > $IRONGATE_SESSION_TIMEOUT)) {
    session_unset();
    session_destroy();
    $authed = false;
    $expired = true;
}

if (!$authed) {
    if ($isApi) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'error' => 'auth_required']);
        exit;
    }
    $current = $_SERVER['REQUEST_URI'] ?? '/';
    header('Location: /login.php?' . ($expired ? 'expired=1&' : '') . 'redirect=' . urlencode($current));
    exit;
}

$_SESSION['last_activity'] = time();
