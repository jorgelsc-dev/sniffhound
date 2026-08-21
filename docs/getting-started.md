# Empezar

## Requisitos

- Python `3.12+`
- Linux o Unix con `AF_PACKET` para captura raw en modo `sniffer`
- privilegios de administrador o `CAP_NET_RAW` para captura en vivo
- Node `22.12.0+` solo si vas a trabajar en `frontend/`

## Instalar

### Desde el paquete Debian (`.deb`)

El workflow `Package Debian` publica el `.deb` en **GitHub Releases**. Tambien puedes construirlo localmente.

Instalacion desde la ultima release:

```bash
mkdir -p /tmp/sniffhound-release
gh release download --repo jorgelsc-dev/sniffhound --pattern '*.deb' --dir /tmp/sniffhound-release
sudo apt install /tmp/sniffhound-release/*.deb
sniffhound
```

La pagina de la ultima release es:

```text
https://github.com/jorgelsc-dev/sniffhound/releases/latest
```

Instalacion manual del artefacto descargado:

```bash
sudo apt install ./sniffhound_<version>_<arch>.deb
```

Fallback con `dpkg`:

```bash
sudo dpkg -i ./sniffhound_<version>_<arch>.deb
sudo apt -f install
```

### Desde el repo

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .
```

### Build local del paquete Debian

Construye la SPA y luego genera el artefacto:

```bash
cd frontend
npm ci
npm run build
cd ..
./scripts/build_deb.sh
sudo apt install ./dist/sniffhound_<version>_<arch>.deb
```

## Arranque rapido

```bash
sniffhound
```

Fallback if your shell has not refreshed the entry point yet:

```bash
python -m sniffhound
```

Notas del launcher:

- usa `45678` por defecto; si esta ocupado, prueba una ventana cercana de 100 puertos y avisa cual usa;
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
- La UI pide el codigo de seguridad al abrirse y lo conserva solo en memoria del tab actual.

## Documentacion local

El sitio publico se compila con MkDocs Material desde `mkdocs.yml`.

```bash
python -m pip install -r requirements-docs.txt
mkdocs serve
```

Abre `http://127.0.0.1:8000` para previsualizar la documentacion y `mkdocs build --strict` para validar el sitio antes de enviar un PR.
