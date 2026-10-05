<?php
declare(strict_types=1);
// XSS Lab — Setup e verificação de ambiente
// Execute via navegador: http://localhost/.../setup.php

if (!in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)) {
    http_response_code(403);
    exit('Setup disponível somente por acesso local.');
}

$erros = [];
$ok = [];

// 1. PHP Version
$phpVer = PHP_VERSION;
if (version_compare($phpVer, '8.0', '>=')) {
    $ok[] = "PHP $phpVer";
} else {
    $erros[] = "PHP $phpVer detectado — requer 8.0 ou superior";
}

// 2. Extensões obrigatórias
foreach (['pdo_mysql', 'mbstring', 'json'] as $ext) {
    if (extension_loaded($ext)) {
        $ok[] = "Extensão $ext carregada";
    } else {
        $erros[] = "Extensão $ext ausente — habilite no php.ini";
    }
}

// 3. Conexão com MySQL
$host = getenv('XSS_DB_HOST') ?: '127.0.0.1';
$port = getenv('XSS_DB_PORT') ?: '3306';
$base = getenv('XSS_DB_NAME') ?: 'app_xss';
$user = getenv('XSS_DB_USER') ?: 'root';
$pass = getenv('XSS_DB_PASS');
$pdo = null;
try {
    $pdo = new PDO("mysql:host=$host;port=$port;charset=utf8mb4", $user, $pass === false ? '' : $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);
    $ok[] = "Conexão MySQL ($host:$port)";
} catch (PDOException $e) {
    $erros[] = 'MySQL inacessível: ' . $e->getMessage();
}

// 4. Banco e tabelas
$dbOk = false;
$tabelasOk = false;
if ($pdo) {
    try {
        $pdo->exec("CREATE DATABASE IF NOT EXISTS `$base` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $pdo->exec("USE `$base`");
        $ok[] = "Banco `$base` disponível";
        $dbOk = true;
    } catch (PDOException $e) {
        $erros[] = 'Falha ao criar banco: ' . $e->getMessage();
    }
}
if ($pdo && $dbOk) {
    try {
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS usuarios (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(40) NOT NULL UNIQUE,
                nome VARCHAR(80) NOT NULL,
                papel ENUM('admin','usuario_comum') NOT NULL
            ) ENGINE=InnoDB
        ");
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS comentarios (
                id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                usuario_id INT UNSIGNED NOT NULL,
                mensagem TEXT NOT NULL,
                criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_criado (criado_em, id),
                CONSTRAINT fk_comentario_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
            ) ENGINE=InnoDB
        ");
        $ok[] = 'Tabelas criadas / verificadas';
        $tabelasOk = true;
    } catch (PDOException $e) {
        $erros[] = 'Falha ao criar tabelas: ' . $e->getMessage();
    }
}
if ($pdo && $tabelasOk) {
    try {
        $pdo->exec("
            INSERT INTO usuarios (username, nome, papel) VALUES
                ('admin','Admin','admin'),
                ('usuario_comum','Usuário comum','usuario_comum')
            ON DUPLICATE KEY UPDATE nome = VALUES(nome), papel = VALUES(papel)
        ");
        $pdo->exec("
            INSERT IGNORE INTO comentarios (id, usuario_id, mensagem) VALUES
                (1, (SELECT id FROM usuarios WHERE username='admin'), 'Bem-vindo ao XSS Lab. Use apenas dados fictícios.'),
                (2, (SELECT id FROM usuarios WHERE username='usuario_comum'), 'O mesmo banco permite comparar HTML interpretado e texto codificado.')
        ");
        $ok[] = 'Dados iniciais inseridos';
    } catch (PDOException $e) {
        $erros[] = 'Falha ao inserir dados: ' . $e->getMessage();
    }
}

// 5. Reset opcional
$resetado = false;
if (isset($_GET['reset']) && $_GET['reset'] === '1' && $pdo && $tabelasOk) {
    try {
        $pdo->exec('DELETE FROM comentarios WHERE id > 2');
        $ok[] = 'Comentários resetados (mantidos os 2 iniciais)';
        $resetado = true;
    } catch (PDOException $e) {
        $erros[] = 'Falha ao resetar: ' . $e->getMessage();
    }
}

// 6. Contagem
$total = 0;
if ($pdo && $tabelasOk) {
    try { $total = (int) $pdo->query('SELECT COUNT(*) FROM comentarios')->fetchColumn(); } catch (PDOException $_) {}
}

// 7. URLs de acesso
$dir = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
$urlVuln = "$dir/codigo-vulneravel/index.php";
$urlSafe = "$dir/codigo-corrigido/index.php";

function esc(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }
?>
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <title>Setup · XSS Lab</title>
    <style>
        *{box-sizing:border-box;margin:0}
        body{font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,sans-serif;background:#FAFAFA;color:#0F172A;padding:40px 24px;-webkit-font-smoothing:antialiased}
        .c{max-width:600px;margin:auto}
        h1{font-size:1.5rem;letter-spacing:-0.02em;font-weight:600;margin-bottom:4px}
        .sub{color:#64748B;font-size:.875rem;margin-bottom:24px}
        .card{background:#FFF;border:1px solid #E2E8F0;border-radius:8px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px 0 rgb(0 0 0/.04)}
        .card h2{font-size:.8125rem;font-weight:600;margin-bottom:12px}
        .item{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:.8125rem;border-bottom:1px solid #F1F5F9}
        .item:last-child{border-bottom:none}
        .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
        .dot-ok{background:#15803D}.dot-err{background:#B91C1C}
        .links{display:flex;gap:10px;flex-wrap:wrap;margin-top:4px}
        a.btn{display:inline-flex;align-items:center;padding:7px 14px;background:#0F172A;color:#FFF;border-radius:6px;text-decoration:none;font-size:.8125rem;font-weight:500}
        a.btn:hover{background:#1E293B}
        a.btn-q{background:transparent;color:#64748B;border:1px solid #E2E8F0}
        a.btn-q:hover{background:#F1F5F9;color:#0F172A}
        .stats{color:#64748B;font-size:.8125rem;margin-top:8px}
        .ft{margin-top:24px;text-align:center;color:#64748B;font-size:.6875rem}
    </style>
</head>
<body>
<div class="c">
    <h1>XSS Lab — Setup</h1>
    <p class="sub">Verificação de ambiente e inicialização do banco de dados.</p>
    <div class="card">
        <h2>Checklist de ambiente</h2>
        <?php foreach ($ok as $msg): ?>
        <div class="item"><span class="dot dot-ok"></span> <?= esc($msg) ?></div>
        <?php endforeach; ?>
        <?php foreach ($erros as $msg): ?>
        <div class="item"><span class="dot dot-err"></span> <?= esc($msg) ?></div>
        <?php endforeach; ?>
        <?php if ($tabelasOk): ?>
        <p class="stats"><?= $total ?> comentário(s) no banco.</p>
        <?php endif; ?>
    </div>
    <?php if (empty($erros)): ?>
    <div class="card">
        <h2>Acessar o laboratório</h2>
        <div class="links">
            <a class="btn" href="<?= esc($urlVuln) ?>">Versão vulnerável</a>
            <a class="btn btn-q" href="<?= esc($urlSafe) ?>">Versão corrigida</a>
        </div>
    </div>
    <?php endif; ?>
    <div class="card">
        <h2>Manutenção</h2>
        <?php if (!$resetado): ?>
        <a class="btn btn-q" href="?reset=1" onclick="return confirm('Apagar todos os comentários exceto os 2 iniciais?')">Resetar comentários</a>
        <?php else: ?>
        <div class="item"><span class="dot dot-ok"></span> Comentários resetados com sucesso.</div>
        <?php endif; ?>
    </div>
    <p class="ft">XSS Lab · Setup · PHP <?= PHP_VERSION ?></p>
</div>
</body>
</html>
