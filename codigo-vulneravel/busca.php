<?php
declare(strict_types=1);
require __DIR__ . '/conexao.php';
exigir_login();
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { falhar(405, 'Método não permitido.'); }
$nome = array_key_exists('q', $_GET) ? 'q' : 'termo';
$termo = campo($_GET, $nome, LIMITE_TERMO);
// busca.php é a entrada canônica; resultado.php também aceita GET diretamente.
header('Location: resultado.php?q=' . rawurlencode($termo), true, 303);
exit;
