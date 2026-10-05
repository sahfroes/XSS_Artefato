-- Laboratório local: execute no phpMyAdmin antes de abrir a aplicação.
-- Não apaga comentários existentes. Reset destrutivo: DROP DATABASE app_xss;
CREATE DATABASE IF NOT EXISTS app_xss CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE app_xss;
CREATE TABLE IF NOT EXISTS usuarios (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(40) NOT NULL UNIQUE,
    nome VARCHAR(80) NOT NULL,
    papel ENUM('admin','usuario_comum') NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS comentarios (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT UNSIGNED NOT NULL,
    mensagem TEXT NOT NULL,
    criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_criado (criado_em, id),
    CONSTRAINT fk_comentario_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
) ENGINE=InnoDB;
INSERT INTO usuarios (username, nome, papel) VALUES
    ('admin','Admin','admin'),
    ('usuario_comum','Usuário comum','usuario_comum')
ON DUPLICATE KEY UPDATE nome = VALUES(nome), papel = VALUES(papel);
-- Idempotência dos exemplos: IDs reservados; não substituem registros já existentes.
INSERT IGNORE INTO comentarios (id, usuario_id, mensagem) VALUES
    (1, (SELECT id FROM usuarios WHERE username='admin'), 'Bem-vindo ao XSS Lab. Use apenas dados fictícios.'),
    (2, (SELECT id FROM usuarios WHERE username='usuario_comum'), 'O mesmo banco permite comparar HTML interpretado e texto codificado.');
