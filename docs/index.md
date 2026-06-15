<div class="hero">

# SniffHound

Capturador y analizador de trafico en Python nativo con SQLite, auth por token, WebSocket en vivo y modo honeypot.

</div>

<div class="meta-grid">
<div class="meta"><span>Sitio publico</span><strong>sniffhound.jorgelsc.dev</strong></div>
<div class="meta"><span>Docs runtime</span><strong>/docs</strong></div>
<div class="meta"><span>Base de datos</span><strong>SniffHound.db</strong></div>
<div class="meta"><span>Modo por defecto</span><strong>sniffer</strong></div>
</div>

## Mapa de plataforma

<div class="diagram">
<div class="diagram-title">Flujo principal</div>
<div class="diagram-track">
<div class="diagram-node">Operador</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-node">Token</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-node">Dashboard</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-node">Runtime</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-node">SQLite + WS</div>
</div>
<div class="diagram-rows" style="margin-top: 1rem;">
<div class="diagram-row">
<div class="diagram-step">Sniffer</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-step">Flows, packets, tags</div>
<div class="diagram-note">Captura Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP e ICMPv6.</div>
</div>
<div class="diagram-row">
<div class="diagram-step">Honeypot</div>
<div class="diagram-arrow">-&gt;</div>
<div class="diagram-step">Banners y respuestas</div>
<div class="diagram-note">Escucha puertos comunes y registra la actividad activa en la misma base.</div>
</div>
</div>
</div>

## Lo esencial

<div class="cards">
<div class="card"><strong>Captura nativa</strong><br>Socket raw, parseo local y control de interfaces.</div>
<div class="card"><strong>Persistencia</strong><br>SQLite con snapshots de sesiones, flows y runtime.</div>
<div class="card"><strong>API y WebSocket</strong><br>Dashboard, metricas y broadcast en tiempo real.</div>
<div class="card"><strong>Documentacion MkDocs</strong><br>Sitio publico en <a href="https://sniffhound.jorgelsc.dev/"><code>sniffhound.jorgelsc.dev</code></a>.</div>
</div>

## Ruta recomendada

1. Empieza por [Empezar](getting-started.md).
2. Revisa [Arquitectura](architecture.md) para entender el flujo.
3. Usa [Referencia](reference/index.md) si necesitas rutas, variables o esquema.
4. Si trabajas en la UI, valida tambien `frontend/` y el runtime `/docs`.
