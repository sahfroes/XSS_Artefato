<?php
declare(strict_types=1);

// A única mudança de configuração entre os ambientes é esta constante.
const APP_CORRIGIDO = false;
const LIMITE_TERMO = 4000;
const LIMITE_COMENTARIO = 6000;
date_default_timezone_set('America/Sao_Paulo');

// Contenção do laboratório: não disponibilizar a versão vulnerável na rede.
// Não confiamos em X-Forwarded-For. Reverse proxies precisam de revisão separada.
if (!in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)) {
    http_response_code(403);
    exit('Laboratório disponível somente por acesso local (loopback).');
}

// Encoder para contexto HTML/texto e atributos entre aspas, NÃO para JS/CSS/URL.
function e($valor): string {
    return htmlspecialchars((string) $valor, ENT_QUOTES, 'UTF-8');
}
function falhar(int $status, string $mensagem): void {
    http_response_code($status);
    header('Content-Type: text/plain; charset=UTF-8');
    exit($mensagem); // Apenas mensagens constantes do programa.
}
function campo(array $origem, string $nome, int $limite): string {
    $valor = $origem[$nome] ?? '';
    if (!is_string($valor) || strlen($valor) > $limite || !preg_match('//u', $valor)) {
        falhar(400, 'Entrada inválida, UTF-8 inválido ou limite de tamanho excedido.');
    }
    return $valor; // Preserva o payload: validação não é escape nem sanitização.
}

$caminho = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/index.php'));
$caminho = rtrim($caminho, '/') . '/';
$https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
$nonce = base64_encode(random_bytes(18));
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
if (APP_CORRIGIDO) {
    // Sem unsafe-inline/unsafe-eval. Somente nosso script recebe o nonce.
    // CSP complementa a codificação; não deve substituir e().
    header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce'; script-src-attr 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'");
    header('X-Frame-Options: DENY');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
}

// A sessão REAL é server-side e protegida nas duas versões.
// Somente os cookies FICTÍCIOS session_id/user são expostos no laboratório vulnerável.
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_name(APP_CORRIGIDO ? 'XSSLAB_SAFE' : 'XSSLAB_VULN');
session_set_cookie_params([
    'lifetime' => 0, 'path' => $caminho, 'secure' => $https,
    'httponly' => true, 'samesite' => 'Lax'
]);
session_start();
if (!isset($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
function validar_csrf(): void {
    $token = campo($_POST, 'csrf', 128);
    if (!hash_equals($_SESSION['csrf'], $token)) {
        falhar(403, 'Formulário expirado ou token CSRF inválido. Recarregue a página.');
    }
}
function cookie_demo(string $nome, string $valor, bool $apagar = false): void {
    global $caminho, $https;
    setcookie($nome, $valor, [
        'expires' => $apagar ? time() - 3600 : 0,
        'path' => $caminho, 'secure' => $https,
        // FALHA no ambiente vulnerável: JS lê os tokens fictícios via document.cookie.
        'httponly' => APP_CORRIGIDO, 'samesite' => 'Lax'
    ]);
}
function exigir_login(): void {
    if (empty($_SESSION['usuario'])) {
        header('Location: index.php', true, 303);
        exit;
    }
}

// Configuração XAMPP padrão. Variáveis de ambiente permitem credenciais diferentes.
// O banco deve existir. Nunca exponha mensagens PDO no navegador.
try {
    $host = getenv('XSS_DB_HOST') ?: '127.0.0.1';
    $port = getenv('XSS_DB_PORT') ?: '3306';
    $base = getenv('XSS_DB_NAME') ?: 'app_xss';
    $user = getenv('XSS_DB_USER') ?: 'root';
    $pass = getenv('XSS_DB_PASS');
    $pdo = new PDO("mysql:host=$host;port=$port;dbname=$base;charset=utf8mb4", $user,
        $pass === false ? '' : $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]);
} catch (PDOException $erro) {
    error_log('XSS Lab: falha na conexão: ' . $erro->getMessage());
    falhar(503, 'Banco indisponível. Importe banco.sql ou rode setup.php.');
}

// Templates internos, compartilhados dentro de cada pasta.
function inicio(string $titulo): void {
    global $nonce;
    $modo = APP_CORRIGIDO ? 'corrigido' : 'vulneravel';
    $usuario = $_SESSION['usuario']['nome'] ?? 'Sem sessão';
    $outraVersao = APP_CORRIGIDO ? '../codigo-vulneravel/index.php' : '../codigo-corrigido/index.php';
    $rotuloVersao = APP_CORRIGIDO ? 'Mudar para Vulnerável ⚠️' : 'Mudar para Corrigido 🛡️';
    ?>
<!doctype html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <title><?= e($titulo) ?> · Security Workspace</title>
    <link rel="stylesheet" href="style.css">
    <!-- Sem defer: hooks precisam existir ANTES dos pontos vulneráveis no body. -->
    <script src="inspector.js" nonce="<?= e($nonce) ?>" data-mode="<?= e($modo) ?>" data-inspector></script>
</head>
<body>
<a class="skip-link" href="#conteudo">Ir para o conteúdo</a>
<header class="topbar">
    <div style="display:flex;align-items:center;gap:16px">
        <a class="brand" href="index.php"><span class="brand-mark" aria-hidden="true">🛡️</span> AppSec<span class="muted">/xss-lab</span></a>
        <nav style="display:flex;gap:12px;font-size:0.8125rem">
            <a href="index.php" style="font-weight:500">Dashboard</a>
            <a href="../setup.php" class="muted" style="text-decoration:none">Setup &amp; Health</a>
        </nav>
    </div>
    <div class="header-meta">
        <a href="<?= e($outraVersao) ?>" class="badge" style="text-decoration:none;font-weight:600"><?= e($rotuloVersao) ?></a>
        <span class="badge <?= APP_CORRIGIDO ? 'badge-safe' : 'badge-risk' ?>"><?= e(strtoupper($modo)) ?></span>
        <span class="user-status"><?= e($usuario) ?></span>
        <?php if (isset($_SESSION['usuario'])): ?>
        <form method="post" action="index.php" class="inline-form">
            <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
            <input type="hidden" name="acao" value="logout">
            <button class="button button-quiet" type="submit" style="padding:4px 8px;min-height:28px">Sair</button>
        </form>
        <?php endif; ?>
    </div>
</header>
<main id="conteudo" class="container">
    <div class="lab-notice">
        <span class="status-dot" aria-hidden="true"></span>
        Ambiente Acadêmico de Pesquisa em Segurança Web · <?= APP_CORRIGIDO ? 'Modo Protegido (Output Encoding + CSP)' : 'Modo Vulnerável (Simulação Intencional)' ?>
    </div>
<?php
}
function telemetria(array $eventos): void {
    $json = json_encode($eventos, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    echo '<div id="telemetry-data" hidden data-events="' . e($json) . '"></div>';
}
function fim(array $eventos = []): void {
    telemetria($eventos);
    ?>
</main>
<footer class="page-footer">
    AppSec Security Workspace · XSS Laboratory (Reflected, Stored &amp; DOM-Based) · PHP 8 / MySQL / Vanilla JS
</footer>
<details id="inspector" class="inspector" open>
    <summary>
        <span class="status-dot" aria-hidden="true"></span> Security Inspector 
        <span id="log-count" class="badge">0 eventos</span>
        <span class="counter-segments">
            <span id="count-alerta" class="counter-seg seg-alerta" title="Alertas de segurança">0</span>
            <span id="count-input" class="counter-seg seg-input" title="Inputs recebidos">0</span>
            <span id="count-defesa" class="counter-seg seg-defesa" title="Sanitizações e defesas">0</span>
            <span id="count-info" class="counter-seg seg-info" title="Eventos de telemetria">0</span>
        </span>
        <span class="inspector-hint">recolher / expandir</span>
    </summary>
    <div class="inspector-toolbar">
        <span id="inspector-mode" class="muted"></span>
        <div class="filter-toggles">
            <button type="button" class="filter-btn active" data-filter="alerta">🔴 Alerta</button>
            <button type="button" class="filter-btn active" data-filter="input">🟡 Input</button>
            <button type="button" class="filter-btn active" data-filter="defesa">🟢 Defesa</button>
            <button type="button" class="filter-btn active" data-filter="info">⚪ Info</button>
        </div>
        <button id="test-cookie" type="button" class="button button-quiet">Testar Cookies</button>
        <button id="export-logs" type="button" class="button button-quiet">Exportar Evidências (JSON)</button>
        <button id="clear-logs" type="button" class="button button-quiet">Limpar</button>
    </div>
    <ol id="inspector-logs" class="inspector-logs" role="log" aria-live="polite" aria-relevant="additions" aria-label="Eventos de segurança"></ol>
    <details class="contrast-panel">
        <summary class="contrast-summary">Matriz de Contraste de Código (Diff de Segurança)</summary>
        <div id="contrast-content" class="contrast-content"></div>
    </details>
    <p class="inspector-note">Telemetria de Segurança Didática · Observabilidade em tempo real de APIs instrumentadas no cliente e servidor.</p>
</details>
</body>
</html>
<?php
}
