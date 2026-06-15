# Empezar

## Requisitos

- Python `3.12+`
- Linux o Unix con `AF_PACKET` para captura raw en modo `sniffer`
- privilegios de administrador o `CAP_NET_RAW` para captura en vivo
- Node `20+` solo si vas a trabajar en `frontend/`

## Instalar

### Desde PyPI

```bash
python -m pip install --upgrade pip
python -m pip install sniffhound
```

### Desde el repo

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## Arranque rapido

```bash
sniffhound
```

Notas del launcher:

- si `45678` esta ocupado, prueba el resto del bloque de 10 puertos y avisa cual usa;
- si faltan privilegios para captura raw y corresponde elevar, intenta relanzarse con `sudo`;
- si solo quieres abrir la UI sin autoarranque de captura, usa `SNIFFHOUND_CAPTURE_AUTO_START=0`.

Ejemplos utiles:

```bash
SNIFFHOUND_CAPTURE_AUTO_START=0 sniffhound
SNIFFHOUND_RUNTIME_MODE=honeypot sniffhound
SNIFFHOUND_CAPTURE_INTERFACES="eth0,wlan0" sniffhound
```

## Acceso

- Dashboard: `http://127.0.0.1:45678`
- Docs runtime: `http://127.0.0.1:45678/docs`
- Catalogo de endpoints: `http://127.0.0.1:45678/api/endpoints/`

## Documentacion local

El sitio publico se compila con MkDocs Material desde `mkdocs.yml`.

```bash
python -m pip install -r requirements-docs.txt
mkdocs serve
```

Abre `http://127.0.0.1:8000` para previsualizar la documentacion y `mkdocs build --strict` para validar el sitio antes de enviar un PR.
