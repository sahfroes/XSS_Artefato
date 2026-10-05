# XSS Security Lab — Application Security Workspace

> **Laboratório Prático de Estudo Comparativo de Vulnerabilidades Cross-Site Scripting (XSS)**  
> Desenvolvido para testes acadêmicos, apresentações de bancas técnicas e simulação defensiva de AppSec.

---

## 📋 Visão Geral

O **XSS Security Lab** é uma aplicação web minimalista de alta densidade informacional projetada para demonstrar, em tempo real, como os três principais vetores de **Cross-Site Scripting (XSS)** se comportam quando submetidos a um ambiente **Vulnerável** versus um ambiente **Protegido (Corrigido)**.

O projeto segue um design minimalista inspirado em ferramentas modernas de desenvolvedores e segurança (como Vercel, Linear e DevTools), utilizando **PHP 8**, **MySQL**, **Vanilla JavaScript** e **CSS Puro** (sem frameworks pesados ou build steps).

---

## 🏛️ Arquitetura e Estrutura do Repositório

```
xss-lab-refatorado/
├── setup.php                   # Script automatizado de verificação de ambiente e reset do banco
├── banco.sql                   # Esquema SQL e dados iniciais idempotentes
├── README.md                   # Documentação técnica e roteiro de apresentação
│
├── codigo-vulneravel/          # Aplicação intencionalmente vulnerável
│   ├── index.php               # Dashboard principal com os 3 módulos XSS e Feed
│   ├── busca.php               # Handler de busca (GET)
│   ├── resultado.php           # Exibição de termo refletido (Reflected XSS Sink)
│   ├── comentario.php          # Handler de persistência no MySQL (POST)
│   ├── conexao.php             # Configuração (APP_CORRIGIDO = false)
│   ├── inspector.js            # Security Inspector & Telemetria no Cliente
│   └── style.css               # Design System (Clean Light Theme)
│
└── codigo-corrigido/           # Aplicação idêntica blindada com boas práticas
    ├── index.php               # Dashboard idêntico
    ├── busca.php               # Handler de busca (GET)
    ├── resultado.php           # Exibição segura com output encoding
    ├── comentario.php          # Handler de persistência no MySQL (POST)
    ├── conexao.php             # Configuração (APP_CORRIGIDO = true + CSP)
    ├── inspector.js            # Security Inspector & Telemetria no Cliente
    └── style.css               # Design System (Clean Light Theme)
```

---

## 🎯 Três Vetores de XSS Cobertos

| Vetor | Módulo | Mecanismo | Classificação | Defesa Aplicada (Corrigido) |
|---|---|---|---|---|
| **Reflected XSS** | 01. Busca & Consulta | Parâmetro `GET` refletido no HTML da página | `CWE-79` · `OWASP A03:2021` | Output encoding com `htmlspecialchars(ENT_QUOTES, 'UTF-8')` |
| **Stored XSS** | 02. Publicar Comentário | Parâmetro `POST` persistido no MySQL e exibido no Feed | `CWE-79` · `OWASP A03:2021` | Armazenamento seguro + Output encoding na renderização |
| **DOM-Based XSS** | 03. Manipulação do DOM | Processamento no cliente via JS (Client-Side Sink) | `CWE-79` · `Client Sink` | Atribuição segura com `textContent` (em vez de `innerHTML`) |

---

## 🔬 Security Inspector (DevTools de Segurança Embutido)

O laboratório inclui uma ferramenta de observabilidade em tempo real integrada à base da página:

- **Hooks Transparentes**: Interceptação não-destrutiva de `alert()`, `console.*`, `document.cookie` e `securitypolicyviolation`.
- **Filtros por Categoria**: Alternância rápida entre `🔴 Alertas`, `🟡 Inputs`, `🟢 Defesas` e `⚪ Telemetria`.
- **Exportação Forense**: Download de laudo técnico em formato `JSON` com hash de integridade `SHA-256`.
- **Matriz de Contraste de Código**: Visualizador interativo de código comparando a sintaxe vulnerável com a versão protegida.
- **Simulação Visual de Impacto**: Cartão de alerta contextual simulando exfiltração de cookies quando o payload executa.

---

## ⚡ Guia Rápido de Instalação e Execução

### Pré-requisitos
- **XAMPP / WAMP / Laragon** com PHP 8.0+ e MySQL/MariaDB ativados.
- Servidor web Apache apontado para o diretório do projeto.

### 1. Inicialização Automatizada (Recomendado)
Acesse no navegador:
```
http://localhost/xss-lab/xss-lab-refatorado/setup.php
```
O script fará o teste dos pré-requisitos, criará o banco `app_xss` e as tabelas com dados iniciais automaticamente.

### 2. Acesso aos Ambientes
- **Versão Vulnerável**: `http://localhost/xss-lab/xss-lab-refatorado/codigo-vulneravel/index.php`
- **Versão Corrigida**: `http://localhost/xss-lab/xss-lab-refatorado/codigo-corrigido/index.php`

---

## 🎬 Roteiro de Demonstração para Banca Avaliadora

1. **Demonstração do Reflected XSS (Módulo 01)**
   - Na versão vulnerável, clique no botão `Script Tag` ou `Img Onerror` no Módulo 01 e clique em **Buscar**.
   - Observe a execução da caixa de alerta/probe e o registro imediato no **Security Inspector** com marcador 🔴 `[ALERTA DE SEGURANÇA]`.
   - Alterne para a versão corrigida (clicando no badge no topo) e repita a operação: o termo será exibido como texto literal seguro.

2. **Demonstração do Stored XSS (Módulo 02)**
   - Na versão vulnerável, selecione o payload `Img Onerror` ou `SVG Onload` e clique em **Publicar Comentário**.
   - O comentário será gravado no MySQL. Sempre que a página ou o feed for recarregado, a vulnerabilidade será acionada.
   - Alterne para a versão corrigida: o histórico existente no mesmo banco é renderizado de forma inofensiva.

3. **Demonstração do DOM-Based XSS (Módulo 03)**
   - No Módulo 03, selecione `Img Onerror` e clique em **Renderizar**.
   - No ambiente vulnerável, a atribuição via `innerHTML` força a interpretação do elemento. No ambiente corrigido, a atribuição via `textContent` trata o payload como nó de texto.

4. **Análise de Evidências e Dif de Código**
   - Na barra inferior, abra a **Matriz de Contraste de Código** para apresentar os snippets de segurança.
   - Clique em **Exportar Evidências (JSON)** para gerar o laudo pericial com hash SHA-256.

---

## 🛡️ Medidas Defensivas Implementadas no Modo Protegido

1. **Context-Aware Output Encoding**: Uso rigoroso de `htmlspecialchars($str, ENT_QUOTES, 'UTF-8')`.
2. **Content Security Policy (CSP)**: `default-src 'none'; script-src 'nonce-{rand}'`. Bloqueia a execução de scripts inline não autorizados.
3. **Cookie Hardening**: `HttpOnly`, `SameSite=Lax`, protegendo os tokens de sessão contra leitura via JavaScript (`document.cookie`).
4. **Client-Side Safe Sinks**: Substituição de `innerHTML` por `textContent` no manipulador do DOM.

---

## 📄 Licença e Uso Acadêmico

Desenvolvido exclusivamente para fins educacionais e de pesquisa acadêmica em Cibersegurança e Engenharia de Software.
