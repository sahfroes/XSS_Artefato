/* Telemetria transparente e didática. Não é sandbox, WAF ou antivírus.
 * Instalada no head antes dos pontos de saída vulneráveis.
 * Todas as mensagens entram no painel por textContent: o console não cria outro XSS.
 */
(() => {
    'use strict';
    const script = document.currentScript;
    const mode = script ? script.dataset.mode : 'desconhecido';
    const safe = mode === 'corrigido';
    const directory = location.pathname.slice(0, location.pathname.lastIndexOf('/') + 1);
    const storageKey = `xss-lab:${mode}:${directory}`;
    const MAX_EVENTS = 160;
    const MAX_TEXT = 6500;
    const labels = {
        alerta: '🔴 [ALERTA DE SEGURANÇA]', input: '🟡 [INPUT RECEBIDO]',
        defesa: '🟢 [SANITIZAÇÃO / DEFESA]', info: '⚪ [TELEMETRIA]'
    };
    let rows = [];
    let list = null;
    let counter = null;
    let cookieHook = false;
    let emitting = false;
    const typeCounts = { alerta: 0, input: 0, defesa: 0, info: 0 };
    const activeFilters = new Set(['alerta', 'input', 'defesa', 'info']);
    const originalConsole = {};
    ['log', 'info', 'warn', 'error', 'debug'].forEach(method => {
        originalConsole[method] = console[method].bind(console);
    });

    function printable(value) {
        try {
            if (typeof value === 'string') return value;
            if (value instanceof Error) return `${value.name}: ${value.message}`;
            return JSON.stringify(value) ?? String(value);
        } catch (_) { return '[valor não serializável]'; }
    }
    function persist() {
        try { sessionStorage.setItem(storageKey, JSON.stringify(rows)); } catch (_) { /* Sem storage: mantém apenas em memória. */ }
    }
    function updateCounterDisplay() {
        Object.keys(typeCounts).forEach(type => {
            const el = document.getElementById(`count-${type}`);
            if (el) el.textContent = typeCounts[type];
        });
    }
    function paint(row) {
        if (!list) return;
        const item = document.createElement('li');
        item.className = `log-entry log-${row.type}`;
        if (!activeFilters.has(row.type)) item.style.display = 'none';
        const stamp = document.createElement('span');
        stamp.className = 'log-time';
        stamp.textContent = row.time;
        const message = document.createElement('span');
        message.textContent = `${labels[row.type]} ${row.message}`;
        item.append(stamp, message);
        list.append(item);
        while (list.childElementCount > MAX_EVENTS) list.firstElementChild.remove();
        list.scrollTop = list.scrollHeight;
        if (counter) counter.textContent = `${rows.length} eventos`;
    }
    function emit(type, message) {
        if (emitting) return;
        emitting = true;
        try {
            type = Object.hasOwn ? (Object.hasOwn(labels, type) ? type : 'info')
                : (Object.prototype.hasOwnProperty.call(labels, type) ? type : 'info');
            const row = { type, message: String(message).slice(0, MAX_TEXT), time: new Date().toLocaleTimeString('pt-BR') };
            rows.push(row);
            if (rows.length > MAX_EVENTS) rows.shift();
            typeCounts[type] = (typeCounts[type] || 0) + 1;
            persist();
            paint(row);
            updateCounterDisplay();
        } finally { emitting = false; }
    }
    // Histórico é não confiável: validado e pintado exclusivamente como texto.
    try {
        const saved = JSON.parse(sessionStorage.getItem(storageKey) || '[]');
        if (Array.isArray(saved)) rows = saved.slice(-MAX_EVENTS).filter(row =>
            row && Object.prototype.hasOwnProperty.call(labels, row.type) &&
            typeof row.message === 'string' && typeof row.time === 'string'
        ).map(row => ({ type: row.type, message: row.message.slice(0, MAX_TEXT), time: row.time.slice(0, 24) }));
    } catch (_) { rows = []; }
    // Reconstrói contadores a partir do histórico restaurado.
    rows.forEach(row => { typeCounts[row.type] = (typeCounts[row.type] || 0) + 1; });

    // Simulação visual de impacto: mostra cartão de exfiltração fictícia.
    function showImpactCard() {
        if (document.getElementById('xss-impact-card')) return;
        const main = document.getElementById('conteudo');
        if (!main) return;
        const card = document.createElement('div');
        card.id = 'xss-impact-card';
        card.className = 'impact-card';
        const title = document.createElement('div');
        title.className = 'impact-title';
        title.textContent = 'Simulação de impacto — Exfiltração de cookie';
        const body = document.createElement('div');
        body.className = 'impact-body';
        const cookies = document.cookie.split(';').map(c => c.trim())
            .filter(c => /^(session_id|user)=/.test(c));
        const lines = [
            ['Cookie capturado:', cookies.length ? cookies.join('; ') : '(nenhum cookie fictício legível)'],
            ['URL de exfiltração:', `https://atacante.exemplo/collect?token=${encodeURIComponent(cookies.join('; '))}`],
            ['Timestamp:', new Date().toISOString()]
        ];
        lines.forEach(([label, value]) => {
            const line = document.createElement('div');
            line.className = 'impact-line';
            const lbl = document.createElement('span');
            lbl.className = 'impact-label';
            lbl.textContent = label;
            const val = document.createElement('code');
            val.textContent = value;
            line.append(lbl, val);
            body.appendChild(line);
        });
        const dismiss = document.createElement('button');
        dismiss.className = 'button button-quiet impact-dismiss';
        dismiss.textContent = 'Fechar simulação';
        dismiss.addEventListener('click', () => card.remove());
        card.append(title, body, dismiss);
        main.insertBefore(card, main.children[1] || null);
    }

    // Não concluímos "script executado" só por encontrar '<script>' no input.
    // Este probe é invocado explicitamente pelo payload didático e prova apenas esta chamada.
    window.SecurityInspector = Object.freeze({
        probe(message = 'Payload demonstrativo executado no contexto da página.') {
            emit('alerta', `Execução JavaScript observada via probe: ${printable(message)}`);
            originalConsole.warn('[XSS-LAB]', message);
            if (!safe) showImpactCard();
        }
    });
    Object.keys(originalConsole).forEach(method => {
        console[method] = (...args) => {
            originalConsole[method](...args);
            const message = args.map(printable).join(' ');
            const kind = message.includes('XSS-LAB') ? 'alerta' : (method === 'warn' ? 'input' : 'info');
            emit(kind, `console.${method}: ${message}`);
        };
    });
    const originalAlert = window.alert.bind(window);
    window.alert = message => {
        emit('alerta', `window.alert invocado: execução JS observada. Mensagem: ${printable(message)}`);
        return originalAlert(message);
    };

    // Instrumentação best-effort: alguns navegadores podem impedir a redefinição.
    // Uma leitura de cookie comprova acesso à API, NÃO roubo/exfiltração.
    try {
        let owner = document;
        let descriptor;
        while (owner && !descriptor) {
            descriptor = Object.getOwnPropertyDescriptor(owner, 'cookie');
            owner = Object.getPrototypeOf(owner);
        }
        if (!descriptor || !descriptor.get || !descriptor.set) throw new Error('Accessor indisponível');
        Object.defineProperty(document, 'cookie', {
            configurable: true, enumerable: descriptor.enumerable,
            get() {
                const value = descriptor.get.call(document);
                emit(safe ? 'input' : 'alerta', 'Leitura observada de document.cookie. Isso não comprova exfiltração.');
                if (safe) {
                    emit(/(?:^|;\s*)session_id=/.test(value) ? 'alerta' : 'defesa',
                        /(?:^|;\s*)session_id=/.test(value)
                            ? 'session_id legível: verifique cookies duplicados/configuração do ambiente.'
                            : 'O cookie fictício session_id não consta na leitura. HttpOnly o exclui da API; cookies de outros apps podem aparecer.');
                }
                return value;
            },
            set(value) { descriptor.set.call(document, value); }
        });
        cookieHook = true;
    } catch (_) {
        emit('info', 'Hook de document.cookie indisponível neste navegador. Use o botão de teste e confirme os atributos no DevTools.');
    }
    document.addEventListener('securitypolicyviolation', event => {
        emit('defesa', `Bloqueio CSP observado: ${event.effectiveDirective}; origem: ${event.blockedURI || 'inline'}.`);
    });
    window.addEventListener('error', event => {
        if (event.message) emit('info', `Erro de runtime observado (não comprova XSS): ${event.message}`);
    });
    emit('info', `Página carregada: ${location.pathname}. Modo: ${mode}. Histórico limitado a ${MAX_EVENTS} eventos nesta aba.`);

    // Executa só após existir o painel; os eventos anteriores ficaram na fila.
    document.addEventListener('DOMContentLoaded', () => {
        list = document.getElementById('inspector-logs');
        counter = document.getElementById('log-count');
        if (!list || !counter) return;
        rows.forEach(paint);
        counter.textContent = `${rows.length} eventos`;
        updateCounterDisplay();
        const modeLabel = document.getElementById('inspector-mode');
        if (modeLabel) modeLabel.textContent = `${mode} · hooks locais · histórico nesta aba`;
        const panel = document.getElementById('inspector');
        if (panel) panel.addEventListener('toggle', () => document.body.classList.toggle('inspector-collapsed', !panel.open));

        // Filtros por tipo de evento.
        document.querySelectorAll('[data-filter]').forEach(btn => {
            btn.addEventListener('click', () => {
                const type = btn.dataset.filter;
                btn.classList.toggle('active');
                if (activeFilters.has(type)) activeFilters.delete(type);
                else activeFilters.add(type);
                list.querySelectorAll('.log-entry').forEach(entry => {
                    const t = ['alerta', 'input', 'defesa', 'info'].find(k => entry.classList.contains(`log-${k}`));
                    if (t) entry.style.display = activeFilters.has(t) ? '' : 'none';
                });
            });
        });

        document.getElementById('clear-logs').addEventListener('click', () => {
            rows = [];
            Object.keys(typeCounts).forEach(t => { typeCounts[t] = 0; });
            // replaceChildren remove nós sem interpretar strings como HTML.
            list.replaceChildren();
            persist();
            counter.textContent = '0 eventos';
            updateCounterDisplay();
        });
        document.getElementById('test-cookie').addEventListener('click', () => {
            emit('info', 'Teste manual do laboratório: esta leitura é legítima, não um ataque.');
            const value = document.cookie;
            if (!cookieHook) emit('info', 'Leitura manual executada; hook automático indisponível.');
            // Mostra só cookies FICTÍCIOS conhecidos; nunca imprime a sessão real PHP.
            const demo = value.split(';').map(part => part.trim()).filter(part => /^(session_id|user)=/.test(part));
            emit(safe ? 'defesa' : 'alerta', demo.length ? `Cookies fictícios legíveis: ${demo.join('; ')}` : 'Nenhum cookie fictício legível nesta página.');
        });

        // Exportação de evidências em JSON com hash SHA-256 de integridade.
        const exportBtn = document.getElementById('export-logs');
        if (exportBtn) exportBtn.addEventListener('click', async () => {
            const payload = {
                meta: {
                    ferramenta: 'XSS Lab — Security Inspector',
                    modo: mode,
                    url: location.href,
                    userAgent: navigator.userAgent,
                    exportadoEm: new Date().toISOString(),
                    totalEventos: rows.length
                },
                eventos: rows.map(r => ({ tipo: r.type, mensagem: r.message, horario: r.time }))
            };
            const json = JSON.stringify(payload, null, 2);
            let hash = '(indisponível neste navegador)';
            try {
                const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(json));
                hash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
            } catch (_) {}
            payload.meta.integridade_sha256 = hash;
            const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `xss-lab-${mode}-${Date.now()}.json`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
            emit('info', `Evidências exportadas: ${rows.length} eventos. SHA-256: ${hash.slice(0, 16)}…`);
        });

        document.querySelectorAll('form[data-input-log]').forEach(form => {
            form.addEventListener('submit', () => {
                const field = form.querySelector('[name="q"], [name="comentario"]');
                if (field) emit('input', `Formulário ${form.method.toUpperCase()}: ${field.value}`);
            });
        });

        // Payloads demonstrativos com contextos diferenciados.
        const demoPayloads = {
            script: '<script>SecurityInspector.probe("tag script");console.log(document.cookie)</script>',
            img: '<img src=x onerror="SecurityInspector.probe(\'img/onerror\')">',
            svg: '<svg onload="SecurityInspector.probe(\'svg/onload\')">',
            attr: '" onfocus="SecurityInspector.probe(\'attribute breakout\')" autofocus="'
        };
        document.querySelectorAll('[data-demo]').forEach(button => {
            button.addEventListener('click', () => {
                const target = document.getElementById(button.dataset.demo);
                if (!target) return;
                const key = button.dataset.payload || 'script';
                const payload = demoPayloads[key] || demoPayloads.script;
                target.value = payload;
                target.focus();
                emit('input', `Payload "${key}" preenchido em #${button.dataset.demo}: ${payload}`);
            });
        });

        // Módulo DOM-Based XSS: processa entrada inteiramente no cliente.
        const domInject = document.getElementById('dom-inject');
        const domInput = document.getElementById('dom-input');
        const domOutput = document.getElementById('dom-output');
        const domResult = document.getElementById('dom-result');
        if (domInject && domInput && domOutput && domResult) {
            function renderDom(value) {
                if (!value) return;
                domResult.style.display = '';
                emit('input', `DOM-Based: entrada recebida: ${value}`);
                if (safe) {
                    domOutput.textContent = value;
                    emit('defesa', 'Renderizado com textContent: HTML tratado como texto puro.');
                } else {
                    domOutput.innerHTML = value;
                    emit('alerta', 'Renderizado com innerHTML: HTML interpretado pelo navegador.');
                }
            }
            domInject.addEventListener('click', () => renderDom(domInput.value));
            domInput.addEventListener('keydown', ev => { if (ev.key === 'Enter') renderDom(domInput.value); });
            // Também lê do hash fragment ao carregar a página.
            const hash = location.hash.substring(1);
            if (hash) {
                try {
                    const decoded = decodeURIComponent(hash);
                    domInput.value = decoded;
                    renderDom(decoded);
                } catch (_) {}
            }
        }

        const data = document.getElementById('telemetry-data');
        if (data) {
            try {
                const events = JSON.parse(data.dataset.events || '[]');
                if (Array.isArray(events)) events.slice(0, MAX_EVENTS).forEach(event => {
                    if (event && typeof event.mensagem === 'string') emit(event.tipo, event.mensagem);
                });
            } catch (_) { emit('info', 'Não foi possível interpretar a telemetria enviada pelo servidor.'); }
        }
        // Presença de marcação ativa é evidência do sink, não de execução efetiva.
        if (!safe) document.querySelectorAll('[data-xss-surface]').forEach(surface => {
            const active = surface.querySelectorAll('script, [onerror], [onload], [onclick]');
            if (active.length) emit('alerta', `Marcação ativa observada no HTML: ${active.length} elemento(s). Isso, isoladamente, não comprova execução.`);
        });

        // Painel de contraste de código: snippets comparativos vulnerável vs. corrigido.
        const contrastContent = document.getElementById('contrast-content');
        if (contrastContent) {
            const items = [
                {
                    titulo: 'Output Encoding (Reflected & Stored XSS)',
                    vulneravel: '<?= $termo ?>                     // Bruto no HTML',
                    corrigido:  '<?= e($termo) ?>                  // htmlspecialchars()',
                    explicacao: 'htmlspecialchars() com ENT_QUOTES e UTF-8 converte <, >, ", \' e & em entidades HTML. A entrada vira texto visível, não código executável.'
                },
                {
                    titulo: 'Cookie Flags (Session Hijacking)',
                    vulneravel: "setcookie('session_id', $token, [\n  'httponly' => false   // JS lê\n]);",
                    corrigido:  "setcookie('session_id', $token, [\n  'httponly' => true    // Bloqueado\n]);",
                    explicacao: 'HttpOnly impede que scripts acessem o cookie via document.cookie, neutralizando exfiltração mesmo que XSS seja explorado com sucesso.'
                },
                {
                    titulo: 'Content Security Policy (Defense in Depth)',
                    vulneravel: '// Nenhum header CSP emitido\n// Qualquer script inline executa',
                    corrigido:  "Content-Security-Policy:\n  script-src 'nonce-{rand}';\n  script-src-attr 'none';",
                    explicacao: 'CSP com nonce permite apenas scripts autorizados pelo servidor. Mesmo com HTML malicioso injetado, o navegador bloqueia a execução.'
                },
                {
                    titulo: 'DOM Sink (DOM-Based XSS)',
                    vulneravel: 'el.innerHTML = userInput;  // HTML',
                    corrigido:  'el.textContent = userInput; // Texto',
                    explicacao: 'innerHTML interpreta a string como HTML, criando elementos e executando event handlers. textContent trata toda entrada como texto literal seguro.'
                }
            ];
            items.forEach(item => {
                const section = document.createElement('div');
                section.className = 'contrast-item';
                const title = document.createElement('div');
                title.className = 'contrast-title';
                title.textContent = item.titulo;
                const grid = document.createElement('div');
                grid.className = 'contrast-grid';
                [['VULNERÁVEL', 'code-danger', item.vulneravel], ['CORRIGIDO', 'code-safe', item.corrigido]].forEach(([label, cls, code]) => {
                    const block = document.createElement('div');
                    block.className = `code-block ${cls}`;
                    const lbl = document.createElement('span');
                    lbl.className = 'code-label';
                    lbl.textContent = label;
                    const pre = document.createElement('pre');
                    const codeEl = document.createElement('code');
                    codeEl.textContent = code;
                    pre.appendChild(codeEl);
                    block.append(lbl, pre);
                    grid.appendChild(block);
                });
                const explanation = document.createElement('p');
                explanation.className = 'contrast-explanation';
                explanation.textContent = item.explicacao;
                section.append(title, grid, explanation);
                contrastContent.appendChild(section);
            });
        }
    });
})();
