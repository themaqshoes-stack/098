<?php
declare(strict_types=1);

require __DIR__ . '/../app/db.php';

session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => !empty($_SERVER['HTTPS']),
]);
session_start();

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function out(array $d, int $code = 200): never
{
    http_response_code($code);
    echo json_encode($d, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function fail(string $msg, int $code = 400): never { out(['error' => $msg], $code); }
function now(): string { return gmdate('Y-m-d H:i:s'); }
function iso(?string $s): ?string { return $s ? str_replace(' ', 'T', $s) . 'Z' : null; }
function csrf(): string { return $_SESSION['csrf'] ??= bin2hex(random_bytes(16)); }

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fail('POST required', 405);
}
$in = json_decode(file_get_contents('php://input') ?: '[]', true);
if (!is_array($in)) { $in = []; }
$action = (string)($_GET['action'] ?? '');
$pdo = db();

function currentUser(PDO $pdo): ?array
{
    if (empty($_SESSION['uid'])) { return null; }
    $s = $pdo->prepare('SELECT id,name,email,role FROM users WHERE id=?');
    $s->execute([$_SESSION['uid']]);
    return $s->fetch() ?: null;
}

/* ---------- public actions ---------- */
if ($action === 'login') {
    $cfg   = require __DIR__ . '/../app/config.php';
    $email = strtolower(trim((string)($in['email'] ?? '')));
    $pass  = (string)($in['password'] ?? '');
    $ip    = $_SERVER['REMOTE_ADDR'] ?? '';
    $since = gmdate('Y-m-d H:i:s', time() - $cfg['lock_minutes'] * 60);
    $pdo->prepare('DELETE FROM login_attempts WHERE at < ?')->execute([$since]);
    $c = $pdo->prepare('SELECT COUNT(*) FROM login_attempts WHERE ip=? AND email=?');
    $c->execute([$ip, $email]);
    if ((int)$c->fetchColumn() >= $cfg['max_attempts']) {
        fail('Too many failed attempts. Try again in ' . $cfg['lock_minutes'] . ' minutes.', 429);
    }
    $s = $pdo->prepare('SELECT * FROM users WHERE email=?');
    $s->execute([$email]);
    $u = $s->fetch();
    if (!$u || !password_verify($pass, $u['password_hash'])) {
        $pdo->prepare('INSERT INTO login_attempts (ip,email,at) VALUES (?,?,?)')->execute([$ip, $email, now()]);
        usleep(400000);
        fail('Incorrect email or password.', 401);
    }
    $pdo->prepare('DELETE FROM login_attempts WHERE ip=? AND email=?')->execute([$ip, $email]);
    session_regenerate_id(true);
    $_SESSION['uid'] = (int)$u['id'];
    unset($_SESSION['csrf']);
    out(['user' => ['id' => (int)$u['id'], 'name' => $u['name'], 'email' => $u['email'], 'role' => $u['role']], 'csrf' => csrf()]);
}
if ($action === 'me') {
    $u = currentUser($pdo);
    out(['user' => $u, 'csrf' => $u ? csrf() : null]);
}

/* ---------- authenticated actions ---------- */
$me = currentUser($pdo);
if (!$me) { fail('Please sign in.', 401); }
if (!hash_equals(csrf(), (string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''))) { fail('Invalid security token. Reload the page.', 403); }
$meId    = (int)$me['id'];
$isAdmin = $me['role'] === 'admin';

function clean(mixed $v, int $max): string
{
    $v = trim((string)$v);
    return mb_substr($v, 0, $max);
}
function requireAdmin(bool $isAdmin): void { if (!$isAdmin) { fail('Admins only.', 403); } }

function getThread(PDO $pdo, int $id, int $meId, bool $isAdmin): array
{
    $s = $pdo->prepare('SELECT t.*, u.name AS user_name, u.email AS user_email FROM threads t JOIN users u ON u.id=t.user_id WHERE t.id=?');
    $s->execute([$id]);
    $t = $s->fetch();
    if (!$t || (!$isAdmin && (int)$t['user_id'] !== $meId)) { fail('Conversation not found.', 404); }
    return $t;
}
function addMessage(PDO $pdo, int $threadId, int $senderId, string $body, bool $senderIsAdmin): void
{
    $pdo->prepare('INSERT INTO messages (thread_id,sender_id,body,created_at) VALUES (?,?,?,?)')->execute([$threadId, $senderId, $body, now()]);
    // bump thread and surface it again for the recipient
    $recipientFlag = $senderIsAdmin ? 'archived_user' : 'archived_admin';
    $pdo->prepare("UPDATE threads SET updated_at=?, $recipientFlag=0 WHERE id=?")->execute([now(), $threadId]);
}

switch ($action) {

    case 'logout':
        $_SESSION = [];
        session_destroy();
        out(['ok' => true]);

    /* ----- list threads + counters ----- */
    case 'threads': {
        $filter = (string)($in['filter'] ?? 'inbox');
        $q      = clean($in['q'] ?? '', 100);
        $arch   = $isAdmin ? 'archived_admin' : 'archived_user';
        $like   = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $q) . '%';

        $sql = "SELECT t.id, t.user_id, t.subject, t.closed, t.$arch AS archived, t.updated_at,
                    u.name AS user_name, u.email AS user_email,
                    (SELECT COUNT(*) FROM messages m WHERE m.thread_id=t.id AND m.sender_id<>:me AND m.read_at IS NULL) AS unread,
                    (SELECT COUNT(*) FROM messages m WHERE m.thread_id=t.id) AS msg_count,
                    (SELECT body FROM messages m WHERE m.thread_id=t.id ORDER BY m.id DESC LIMIT 1) AS last_body,
                    (SELECT sender_id FROM messages m WHERE m.thread_id=t.id ORDER BY m.id DESC LIMIT 1) AS last_sender,
                    CASE WHEN :q = '' THEN 1
                         WHEN t.subject LIKE :like ESCAPE '\\' OR u.name LIKE :like ESCAPE '\\'
                              OR EXISTS (SELECT 1 FROM messages m WHERE m.thread_id=t.id AND m.body LIKE :like ESCAPE '\\') THEN 1
                         ELSE 0 END AS hit
                FROM threads t JOIN users u ON u.id=t.user_id
                WHERE " . ($isAdmin ? '1=1' : 't.user_id=:uid') . '
                ORDER BY t.updated_at DESC, t.id DESC';
        $p = [':me' => $meId, ':q' => $q, ':like' => $like];
        if (!$isAdmin) { $p[':uid'] = $meId; }
        $st = $pdo->prepare($sql);
        $st->execute($p);
        $all = $st->fetchAll();

        $counts = ['inbox' => 0, 'unread' => 0, 'sent' => 0, 'archived' => 0];
        $stats  = ['total' => 0, 'unread' => 0, 'awaiting' => 0, 'closed' => 0, 'users' => 0, 'today' => 0];
        $list   = [];
        $adminName = 'Administration';
        $todayStart = gmdate('Y-m-d 00:00:00');

        foreach ($all as $r) {
            $arc = (int)$r['archived'] === 1;
            $unread = (int)$r['unread'];
            $sentByMe = (int)$r['last_sender'] === $meId;
            if ($arc) { $counts['archived']++; }
            else {
                $counts['inbox']++;
                if ($unread > 0) { $counts['unread']++; }
                if ($sentByMe) { $counts['sent']++; }
                if (!$sentByMe) { $stats['awaiting']++; }
            }
            $stats['total']++;
            $stats['unread'] += $unread;
            if ((int)$r['closed'] === 1) { $stats['closed']++; }

            $match = match ($filter) {
                'archived' => $arc,
                'unread'   => !$arc && $unread > 0,
                'sent'     => !$arc && $sentByMe,
                default    => !$arc,
            };
            if ($match && (int)$r['hit'] === 1) {
                $list[] = [
                    'id' => (int)$r['id'], 'subject' => $r['subject'],
                    'peer_name'  => $isAdmin ? $r['user_name'] : $adminName,
                    'peer_email' => $isAdmin ? $r['user_email'] : null,
                    'preview' => mb_substr((string)$r['last_body'], 0, 140),
                    'last_from_me' => $sentByMe,
                    'unread' => $unread, 'msg_count' => (int)$r['msg_count'],
                    'closed' => (bool)$r['closed'], 'archived' => $arc,
                    'updated_at' => iso($r['updated_at']),
                ];
            }
        }
        $t = $pdo->prepare('SELECT COUNT(*) FROM messages WHERE created_at >= ?' . ($isAdmin ? '' : ' AND thread_id IN (SELECT id FROM threads WHERE user_id=' . $meId . ')'));
        $t->execute([$todayStart]);
        $stats['today'] = (int)$t->fetchColumn();
        if ($isAdmin) { $stats['users'] = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role='user'")->fetchColumn(); }

        out(['threads' => $list, 'counts' => $counts, 'stats' => $stats]);
    }

    /* ----- open a thread (marks the other party's messages as read) ----- */
    case 'thread': {
        $t = getThread($pdo, (int)($in['id'] ?? 0), $meId, $isAdmin);
        $pdo->prepare('UPDATE messages SET read_at=? WHERE thread_id=? AND sender_id<>? AND read_at IS NULL')->execute([now(), $t['id'], $meId]);
        $s = $pdo->prepare('SELECT m.id,m.sender_id,m.body,m.created_at,m.read_at,u.name AS sender_name,u.role AS sender_role
                            FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.thread_id=? ORDER BY m.id');
        $s->execute([$t['id']]);
        $msgs = array_map(fn($m) => [
            'id' => (int)$m['id'], 'sender_id' => (int)$m['sender_id'], 'sender_name' => $m['sender_name'],
            'sender_role' => $m['sender_role'], 'body' => $m['body'],
            'created_at' => iso($m['created_at']), 'read_at' => iso($m['read_at']),
        ], $s->fetchAll());
        out(['thread' => [
            'id' => (int)$t['id'], 'subject' => $t['subject'], 'closed' => (bool)$t['closed'],
            'archived' => (bool)$t[$isAdmin ? 'archived_admin' : 'archived_user'],
            'peer_name' => $isAdmin ? $t['user_name'] : 'Administration',
            'peer_email' => $isAdmin ? $t['user_email'] : null,
            'messages' => $msgs,
        ]]);
    }

    /* ----- start new conversation(s) ----- */
    case 'send': {
        $subject = clean($in['subject'] ?? '', 150);
        $body    = clean($in['body'] ?? '', 5000);
        if ($subject === '' || $body === '') { fail('Subject and message are required.'); }

        if ($isAdmin) {
            $ids = array_values(array_unique(array_map('intval', (array)($in['user_ids'] ?? []))));
            if (!$ids) { fail('Choose at least one recipient.'); }
            $ph = implode(',', array_fill(0, count($ids), '?'));
            $s = $pdo->prepare("SELECT id FROM users WHERE role='user' AND id IN ($ph)");
            $s->execute($ids);
            $valid = array_map('intval', $s->fetchAll(PDO::FETCH_COLUMN));
            if (!$valid) { fail('No valid recipients.'); }
        } else {
            $valid = [$meId];
        }
        $created = [];
        $pdo->beginTransaction();
        foreach ($valid as $uid) {
            $pdo->prepare('INSERT INTO threads (user_id,subject,created_at,updated_at) VALUES (?,?,?,?)')->execute([$uid, $subject, now(), now()]);
            $tid = (int)$pdo->lastInsertId();
            addMessage($pdo, $tid, $meId, $body, $isAdmin);
            $created[] = $tid;
        }
        $pdo->commit();
        out(['ids' => $created]);
    }

    case 'reply': {
        $t = getThread($pdo, (int)($in['thread_id'] ?? 0), $meId, $isAdmin);
        $body = clean($in['body'] ?? '', 5000);
        if ($body === '') { fail('Write a message first.'); }
        if ((int)$t['closed'] === 1) {
            if (!$isAdmin) { fail('This conversation was closed by the admin.', 403); }
            $pdo->prepare('UPDATE threads SET closed=0 WHERE id=?')->execute([$t['id']]); // admin reply reopens
        }
        addMessage($pdo, (int)$t['id'], $meId, $body, $isAdmin);
        out(['ok' => true]);
    }

    case 'mark': {
        $t = getThread($pdo, (int)($in['thread_id'] ?? 0), $meId, $isAdmin);
        if (!empty($in['unread'])) {
            $s = $pdo->prepare('UPDATE messages SET read_at=NULL WHERE id=(SELECT MAX(id) FROM messages WHERE thread_id=? AND sender_id<>?)');
            $s->execute([$t['id'], $meId]);
            if ($s->rowCount() === 0) { fail('There is no incoming message to mark as unread.'); }
        } else {
            $pdo->prepare('UPDATE messages SET read_at=? WHERE thread_id=? AND sender_id<>? AND read_at IS NULL')->execute([now(), $t['id'], $meId]);
        }
        out(['ok' => true]);
    }

    case 'archive': {
        $t = getThread($pdo, (int)($in['thread_id'] ?? 0), $meId, $isAdmin);
        $col = $isAdmin ? 'archived_admin' : 'archived_user';
        $pdo->prepare("UPDATE threads SET $col=? WHERE id=?")->execute([empty($in['archived']) ? 0 : 1, $t['id']]);
        out(['ok' => true]);
    }

    case 'close': {
        requireAdmin($isAdmin);
        $t = getThread($pdo, (int)($in['thread_id'] ?? 0), $meId, true);
        $pdo->prepare('UPDATE threads SET closed=? WHERE id=?')->execute([empty($in['closed']) ? 0 : 1, $t['id']]);
        out(['ok' => true]);
    }

    case 'delete': {
        requireAdmin($isAdmin);
        $t = getThread($pdo, (int)($in['thread_id'] ?? 0), $meId, true);
        $pdo->prepare('DELETE FROM threads WHERE id=?')->execute([$t['id']]);
        out(['ok' => true]);
    }

    /* ----- user management (admin) ----- */
    case 'users': {
        requireAdmin($isAdmin);
        $rows = $pdo->query("SELECT u.id,u.name,u.email,u.created_at,
                (SELECT COUNT(*) FROM threads t WHERE t.user_id=u.id) AS threads,
                (SELECT COUNT(*) FROM messages m JOIN threads t ON t.id=m.thread_id WHERE t.user_id=u.id AND m.sender_id=u.id AND m.read_at IS NULL) AS unread_from_user,
                (SELECT MAX(m.created_at) FROM messages m JOIN threads t ON t.id=m.thread_id WHERE t.user_id=u.id) AS last_activity
            FROM users u WHERE u.role='user' ORDER BY u.name")->fetchAll();
        out(['users' => array_map(fn($r) => [
            'id' => (int)$r['id'], 'name' => $r['name'], 'email' => $r['email'],
            'threads' => (int)$r['threads'], 'unread_from_user' => (int)$r['unread_from_user'],
            'last_activity' => iso($r['last_activity']), 'created_at' => iso($r['created_at']),
        ], $rows)]);
    }

    case 'create_user': {
        requireAdmin($isAdmin);
        $name  = clean($in['name'] ?? '', 80);
        $email = strtolower(clean($in['email'] ?? '', 120));
        $pass  = (string)($in['password'] ?? '');
        if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) { fail('Enter a name and a valid email.'); }
        if (strlen($pass) < 8) { fail('Password must be at least 8 characters.'); }
        try {
            $pdo->prepare("INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,'user',?)")
                ->execute([$name, $email, password_hash($pass, PASSWORD_DEFAULT), now()]);
        } catch (PDOException $e) {
            fail('That email is already registered.');
        }
        out(['id' => (int)$pdo->lastInsertId()]);
    }

    default:
        fail('Unknown action.', 404);
}
