<?php
declare(strict_types=1);
require __DIR__ . '/conexao.php';
exigir_login();
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { falhar(405, 'Método não permitido.'); }
$nome = array_key_exists('q', $_GET) ? 'q' : 'termo';
$termo = campo($_GET, $nome, LIMITE_TERMO);
// Parametrização em AMBAS: o escopo é XSS, não SQL Injection.
$consulta = $pdo->prepare('SELECT c.id, c.mensagem, c.criado_em, u.nome FROM comentarios c JOIN usuarios u ON u.id=c.usuario_id WHERE c.mensagem LIKE :termo ORDER BY c.id DESC LIMIT 50');
$consulta->execute(['termo' => '%' . $termo . '%']);
$resultados = $consulta->fetchAll();
$eventos = [['tipo' => 'input', 'mensagem' => 'GET bruto recebido: ' . $termo]];
inicio('Resultados da busca');
?>
<section class="hero">
    <div>
        <a class="back-link" href="index.php">← Voltar ao Dashboard</a>
        <h1>Resultados da Consulta Refletida</h1>
        <p class="muted">O termo abaixo demonstra o tratamento do parâmetro GET <?= APP_CORRIGIDO ? '(codificado no servidor)' : '(refletido sem escape)' ?>.</p>
    </div>
</section>
<section class="card stack">
    <form action="busca.php" method="get" class="stack" data-input-log>
        <label for="q">Nova consulta</label>
        <!-- Atributos ficam codificados nas DUAS versões: isolamos a falha no corpo HTML. -->
        <div class="input-row">
            <input id="q" type="text" name="q" value="<?= e($termo) ?>" maxlength="4000">
            <button class="button button-primary" type="submit">Buscar</button>
        </div>
    </form>
    <div class="demo-actions" style="margin:8px 0">
        <div class="eyebrow" style="margin-bottom:6px">Payloads demonstrativos:</div>
        <div class="payload-group">
            <button type="button" class="button button-quiet" data-demo="q" data-payload="script">Script Tag</button>
            <button type="button" class="button button-quiet" data-demo="q" data-payload="img">Img Onerror</button>
            <button type="button" class="button button-quiet" data-demo="q" data-payload="svg">SVG Onload</button>
            <button type="button" class="button button-quiet" data-demo="q" data-payload="attr">Attr Breakout</button>
        </div>
    </div>
    <div class="result-term">
        <span class="eyebrow">TERMO RECEBIDO NO SERVIDOR (<?= APP_CORRIGIDO ? 'htmlspecialchars' : 'raw HTML' ?>)</span>
        <!-- FALHA INTENCIONAL na versão vulnerável / ESCAPE na versão corrigida -->
        <div class="term-value" data-xss-surface><?= APP_CORRIGIDO ? e($termo) : $termo ?></div>
    </div>
    <p class="muted small"><?= e(count($resultados)) ?> resultado(s) encontrado(s) para o termo.</p>
</section>
<section class="card feed-card">
    <h2>Comentários Encontrados</h2>
    <?php if (!$resultados): ?><p class="empty-state">Nenhum comentário corresponde à consulta.</p><?php endif; ?>
    <?php foreach ($resultados as $comentario): ?>
    <article class="comment">
        <div class="comment-meta">
            <span class="avatar" aria-hidden="true"><?= e(substr($comentario['nome'], 0, 1)) ?></span>
            <strong><?= e($comentario['nome']) ?></strong>
            <time><?= e($comentario['criado_em']) ?></time>
        </div>
        <div class="comment-body" data-xss-surface><?= APP_CORRIGIDO ? e($comentario['mensagem']) : $comentario['mensagem'] ?></div>
    </article>
    <?php endforeach; ?>
</section>
<?php
$eventos[] = ['tipo' => APP_CORRIGIDO ? 'defesa' : 'info', 'mensagem' => APP_CORRIGIDO
    ? 'Termo e comentários codificados com htmlspecialchars(ENT_QUOTES, UTF-8). O inspector usa somente textContent.'
    : 'Termo refletido sem escape no HTML. A execução depende do payload e do contexto do navegador.'];
fim($eventos);
