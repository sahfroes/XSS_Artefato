<?php
declare(strict_types=1);
require __DIR__ . '/conexao.php';
exigir_login();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { falhar(405, 'Use POST para publicar comentários.'); }
validar_csrf();
$mensagem = campo($_POST, 'comentario', LIMITE_COMENTARIO);
if (trim($mensagem) === '') { falhar(422, 'Digite uma mensagem não vazia.'); }

// Armazenamento fiel: NÃO aplicamos htmlspecialchars nem strip_tags no banco.
// Prepared statements separam SQL de dados; não neutralizam XSS na exibição.
// Mantidos nas duas versões para não introduzir SQL Injection fora do escopo.
try {
    $stmt = $pdo->prepare('INSERT INTO comentarios (usuario_id, mensagem) VALUES (:usuario, :mensagem)');
    $stmt->execute(['usuario' => (int) $_SESSION['usuario']['id'], 'mensagem' => $mensagem]);
} catch (PDOException $erro) {
    error_log('XSS Lab: falha ao publicar: ' . $erro->getMessage());
    falhar(503, 'Não foi possível publicar. Confira o banco e tente novamente.');
}
$_SESSION['avisos'] = [
    ['tipo' => 'input', 'mensagem' => 'POST bruto recebido e persistido: ' . $mensagem],
    ['tipo' => APP_CORRIGIDO ? 'defesa' : 'info', 'mensagem' => APP_CORRIGIDO
        ? 'INSERT parametrizado. O conteúdo bruto será codificado no momento da exibição.'
        : 'INSERT parametrizado. A falha Stored XSS está na renderização sem escape no feed.']
];
// Post/Redirect/Get evita duplicação por recarregamento.
header('Location: index.php', true, 303);
exit;
