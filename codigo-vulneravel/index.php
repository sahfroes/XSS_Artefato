<?php
declare(strict_types=1);
require __DIR__ . '/conexao.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validar_csrf();
    $acao = campo($_POST, 'acao', 20);
    if ($acao === 'login') {
        $perfil = campo($_POST, 'perfil', 40);
        if (!in_array($perfil, ['admin', 'usuario_comum'], true)) {
            falhar(400, 'Perfil inválido.');
        }
        // Login rápido é uma SIMULAÇÃO; não há autenticação de produção por senha.
        $consulta = $pdo->prepare('SELECT id, username, nome, papel FROM usuarios WHERE username = :perfil');
        $consulta->execute(['perfil' => $perfil]);
        $usuario = $consulta->fetch();
        if (!$usuario) { falhar(503, 'Perfis ausentes. Importe os dados iniciais pelo setup.php.'); }
        session_regenerate_id(true);
        $_SESSION['usuario'] = $usuario;
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        cookie_demo('session_id', $perfil === 'admin' ? 'TOKEN_SECRETO_ADMIN_123' : 'TOKEN_SECRETO_USUARIO_456');
        cookie_demo('user', $usuario['nome']);
        $_SESSION['avisos'] = [['tipo' => 'info', 'mensagem' => 'Sessão de simulação iniciada para ' . $usuario['nome'] . '.']];
    } elseif ($acao === 'logout') {
        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        cookie_demo('session_id', '', true);
        cookie_demo('user', '', true);
    } else { falhar(400, 'Ação inválida.'); }
    header('Location: index.php', true, 303);
    exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { falhar(405, 'Método não permitido.'); }
inicio('Dashboard');
$eventos = $_SESSION['avisos'] ?? [];
unset($_SESSION['avisos']);
if (empty($_SESSION['usuario'])):
?>
<section class="login-shell">
    <div class="card login-card">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
            <span class="eyebrow">AUTENTICAÇÃO DE SEGURANÇA</span>
            <span class="badge <?= APP_CORRIGIDO ? 'badge-safe' : 'badge-risk' ?>"><?= APP_CORRIGIDO ? 'Corrigido' : 'Vulnerável' ?></span>
        </div>
        <h1>AppSec Workspace</h1>
        <p class="muted">Acesse o ambiente interativo para comparar execuções de payloads XSS em tempo real.</p>
        <form method="post" action="index.php" class="stack">
            <input type="hidden" name="acao" value="login">
            <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
            <label for="perfil">Selecione um perfil de demonstração</label>
            <select name="perfil" id="perfil">
                <option value="admin">Administrador (Admin)</option>
                <option value="usuario_comum">Usuário Convidados (usuario_comum)</option>
            </select>
            <button class="button button-primary" type="submit" style="margin-top:6px">Iniciar Sessão de Teste →</button>
        </form>
        <p class="small muted" style="margin-top:16px">Autenticação simulada para fins didáticos. Nenhum dado sensível real é processado.</p>
    </div>
</section>
<?php
else:
    $total = (int) $pdo->query('SELECT COUNT(*) FROM comentarios')->fetchColumn();
    $comentarios = $pdo->query('SELECT c.id, c.mensagem, c.criado_em, u.nome FROM comentarios c JOIN usuarios u ON u.id=c.usuario_id ORDER BY c.id DESC LIMIT 50')->fetchAll();
?>
<section class="hero">
    <div>
        <span class="eyebrow">APPLICATION SECURITY WORKSPACE</span>
        <h1>Análise Comparativa de Vulnerabilidade XSS</h1>
        <p class="muted">Um input. Dois tratamentos. Teste os 3 vetores de Cross-Site Scripting no modo <?= APP_CORRIGIDO ? 'protegido' : 'vulnerável' ?>.</p>
    </div>
    <div class="hero-counter">
        <strong><?= e($total) ?></strong>
        <span class="muted">registros no MySQL</span>
    </div>
</section>

<div class="dashboard-grid">
    <!-- Módulo 01: Reflected XSS -->
    <section class="card">
        <div class="card-heading">
            <span class="step">01</span>
            <div>
                <h2>Busca e Consulta <a href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener" class="cwe-ref">CWE-79 · Reflected</a></h2>
                <p class="muted small">Reflected XSS · Parâmetro GET</p>
            </div>
        </div>
        <form action="busca.php" method="get" class="stack" data-input-log>
            <label for="q">Termo de pesquisa</label>
            <div class="input-row">
                <input id="q" name="q" type="text" placeholder="Pesquisar comentários ou inserir payload" maxlength="4000" required>
                <button class="button button-primary" type="submit">Buscar</button>
            </div>
        </form>
        <div class="demo-actions">
            <div class="eyebrow" style="margin-bottom:6px">Payloads demonstrativos:</div>
            <div class="payload-group">
                <button type="button" class="button button-quiet" data-demo="q" data-payload="script">Script Tag</button>
                <button type="button" class="button button-quiet" data-demo="q" data-payload="img">Img Onerror</button>
                <button type="button" class="button button-quiet" data-demo="q" data-payload="svg">SVG Onload</button>
                <button type="button" class="button button-quiet" data-demo="q" data-payload="attr">Attr Breakout</button>
            </div>
        </div>
        <div class="defense-card">
            <span class="eyebrow">COMPORTAMENTO DO SERVIDOR</span>
            <p><?= APP_CORRIGIDO ? 'Termo de busca codificado com htmlspecialchars() na saída HTML. Tags viram entidades texto.' : 'Termo de busca refletido diretamente no HTML sem sanitização ou escape.' ?></p>
        </div>
    </section>

    <!-- Módulo 02: Stored XSS -->
    <section class="card">
        <div class="card-heading">
            <span class="step">02</span>
            <div>
                <h2>Publicar Comentário <a href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener" class="cwe-ref">CWE-79 · Stored</a></h2>
                <p class="muted small">Stored XSS · POST + MySQL</p>
            </div>
        </div>
        <form action="comentario.php" method="post" class="stack" data-input-log>
            <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
            <label for="comentario">Mensagem</label>
            <textarea id="comentario" name="comentario" rows="3" maxlength="6000" placeholder="Escreva uma mensagem ou insira um payload" required></textarea>
            <div class="demo-actions" style="margin:6px 0">
                <div class="eyebrow" style="margin-bottom:6px">Payloads demonstrativos:</div>
                <div class="payload-group">
                    <button type="button" class="button button-quiet" data-demo="comentario" data-payload="script">Script Tag</button>
                    <button type="button" class="button button-quiet" data-demo="comentario" data-payload="img">Img Onerror</button>
                    <button type="button" class="button button-quiet" data-demo="comentario" data-payload="svg">SVG Onload</button>
                    <button type="button" class="button button-quiet" data-demo="comentario" data-payload="attr">Attr Breakout</button>
                </div>
            </div>
            <div class="form-actions">
                <button class="button button-primary" type="submit" style="width:100%">Publicar comentário</button>
            </div>
        </form>
        <div class="defense-card">
            <span class="eyebrow">PERSISTÊNCIA &amp; RENDERIZAÇÃO</span>
            <p><?= APP_CORRIGIDO ? 'Mensagens são armazenadas puras no MySQL e sanitizadas na renderização com htmlspecialchars().' : 'Mensagens são armazenadas e renderizadas como HTML puro no feed, permitindo execução persistente.' ?></p>
        </div>
    </section>

    <!-- Módulo 03: DOM-Based XSS -->
    <section class="card">
        <div class="card-heading">
            <span class="step">03</span>
            <div>
                <h2>Manipulação do DOM <a href="https://cwe.mitre.org/data/definitions/79.html" target="_blank" rel="noopener" class="cwe-ref">CWE-79 · DOM Sink</a></h2>
                <p class="muted small">DOM-Based XSS · Client-Side Only</p>
            </div>
        </div>
        <div class="stack">
            <label for="dom-input">Entrada Client-Side (ou via URL hash #)</label>
            <div class="input-row">
                <input id="dom-input" type="text" placeholder="Cole o payload ou use um dos exemplos" maxlength="4000">
                <button id="dom-inject" class="button button-primary" type="button">Renderizar</button>
            </div>
        </div>
        <div class="demo-actions" style="margin:6px 0">
            <div class="eyebrow" style="margin-bottom:6px">Payloads demonstrativos:</div>
            <div class="payload-group">
                <button type="button" class="button button-quiet" data-demo="dom-input" data-payload="script">Script Tag</button>
                <button type="button" class="button button-quiet" data-demo="dom-input" data-payload="img">Img Onerror</button>
                <button type="button" class="button button-quiet" data-demo="dom-input" data-payload="svg">SVG Onload</button>
                <button type="button" class="button button-quiet" data-demo="dom-input" data-payload="attr">Attr Breakout</button>
            </div>
        </div>
        <div id="dom-result" class="result-term" style="display:none;margin-top:10px">
            <span class="eyebrow">DOM SINK OUTPUT (<?= APP_CORRIGIDO ? 'textContent' : 'innerHTML' ?>)</span>
            <div id="dom-output" class="term-value" <?= APP_CORRIGIDO ? '' : 'data-xss-surface' ?>></div>
        </div>
        <div class="defense-card">
            <span class="eyebrow">DOM SINK &amp; CLIENT SECURITY</span>
            <p><?= APP_CORRIGIDO ? 'Atribuição via textContent trata o texto como nó literal, neutralizando a injeção.' : 'Atribuição insegura via innerHTML força o navegador a analisar e executar tags HTML.' ?></p>
        </div>
    </section>
</div>

<section class="card feed-card">
    <div class="feed-heading">
        <div>
            <h2>Feed de Comentários em Tempo Real</h2>
            <p class="muted small">Até 50 publicações recentes · Persistência MySQL no banco <code>app_xss</code></p>
        </div>
        <span class="badge <?= APP_CORRIGIDO ? 'badge-safe' : 'badge-risk' ?>"><?= APP_CORRIGIDO ? 'Feed Sanitizado' : 'Feed Vulnerável' ?></span>
    </div>
    <?php if (!$comentarios): ?>
        <p class="empty-state">Nenhum comentário publicado no banco de dados.</p>
    <?php endif; ?>
    <div class="feed">
    <?php foreach ($comentarios as $comentario): ?>
        <article class="comment">
            <div class="comment-meta">
                <span class="avatar" aria-hidden="true"><?= e(substr($comentario['nome'], 0, 1)) ?></span>
                <strong><?= e($comentario['nome']) ?></strong>
                <time><?= e($comentario['criado_em']) ?></time>
                <span class="muted">#<?= e($comentario['id']) ?></span>
            </div>
            <!-- FALHA INTENCIONAL na versão vulnerável / ESCAPE na versão corrigida -->
            <div class="comment-body" data-xss-surface><?= APP_CORRIGIDO ? e($comentario['mensagem']) : $comentario['mensagem'] ?></div>
        </article>
        <?php $eventos[] = ['tipo' => 'input', 'mensagem' => 'Comentário #' . $comentario['id'] . ' recebido do banco: ' . $comentario['mensagem']]; ?>
    <?php endforeach; ?>
    </div>
</section>
<?php
    $eventos[] = ['tipo' => APP_CORRIGIDO ? 'defesa' : 'info', 'mensagem' => APP_CORRIGIDO
        ? 'Feed renderizado com htmlspecialchars(ENT_QUOTES, UTF-8). HTML vira texto seguro.'
        : 'Feed renderizado sem escape. Presença de payload não comprova execução; observe o Inspector.'];
endif;
fim($eventos);
