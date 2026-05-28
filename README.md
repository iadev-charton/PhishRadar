# PhishWatch

PhishWatch es un MVP defensivo y preventivo para monitorizar dominios sospechosos parecidos a una URL legítima. Ayuda a detectar typosquatting, homoglyph/homograph attacks, brand impersonation y registros observados en fuentes OSINT.

## Uso responsable

La herramienta está diseñada exclusivamente para defensa, alerta temprana y protección de marca. No explota vulnerabilidades, no prueba credenciales, no envía formularios, no hace fuzzing y limita sus interacciones activas a DNS, TLS y HTTP HEAD/GET controlados con timeouts y `User-Agent` identificable.

## Arquitectura

- **FastAPI** expone `/docs` y endpoints REST bajo `/v1`.
- **SQLAlchemy 2.x / Alembic** modelan Seeds, Variants, Observations, Verifications, Findings y Jobs.
- **Celery + Redis** procesan análisis asíncronos.
- **PostgreSQL** persiste hallazgos.
- **Collectors** desacoplados permiten mock feed local y conectores preparados para urlscan, PhishTank, Safe Browsing/Web Risk, CertStream, WhoisXML NRD y CZDS.
- **Services** separan canonicalización, generación de variantes, matching, verificación, scoring y exportación.

## Instalación local

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
pytest
uvicorn phishwatch.app.main:app --reload
```

Por defecto local usa SQLite si no se configura `DATABASE_URL`; Docker usa PostgreSQL.

## Uso con Docker

```bash
docker compose up --build
```

Luego abre `http://localhost:8000/docs`.

## Ejemplo de análisis

```bash
curl -X POST http://localhost:8000/v1/analyze \
  -H 'content-type: application/json' \
  -d '{
    "url": "https://login.ejemplo.com/portal",
    "options": {"active_verification": false, "tlds": ["com", "net", "org", "es", "co", "io"]},
    "sources": ["mock_feed"]
  }'
```

Consulta el job con `GET /v1/jobs/{job_id}`, findings con `GET /v1/findings` y exporta con `/v1/export/findings.csv` o `/v1/export/findings.json`.

## Variables de entorno

Consulta `.env.example`. Las claves comerciales son opcionales. Si una clave falta, el collector queda deshabilitado y registra un warning controlado.

## Añadir collectors

1. Hereda de `BaseCollector` en `phishwatch/app/collectors/base.py`.
2. Implementa `name`, `is_enabled()` y `collect(context)`.
3. Devuelve `ObservationCandidate` minimizados.
4. Registra el collector en `phishwatch/app/collectors/__init__.py`.
5. Lee credenciales desde `Settings` y no rompas la app si faltan.

## Tests

```bash
pytest
ruff check .
```

## Limitaciones del MVP

- Los conectores comerciales quedan preparados, pero requieren claves o feeds locales.
- No hay UI web todavía.
- La verificación HTTP no ejecuta JavaScript y solo captura metadatos mínimos.
- El skeleton homoglyph es controlado y limitado para evitar explosión combinatoria.

## Roadmap técnico

### Fase 1 - MVP local

- FastAPI;
- workers;
- mock feed;
- generación de variantes;
- DNS/TLS/HTTP verification;
- scoring;
- export JSON/CSV.

### Fase 2 - Fuentes reales

- urlscan;
- PhishTank;
- Safe Browsing / Web Risk;
- CertStream;
- WhoisXML NRD;
- CZDS local files.

### Fase 3 - Enriquecimiento avanzado

- screenshots;
- favicon hash;
- fuzzy hashing HTML;
- perceptual hash visual;
- comparación con sitio legítimo;
- integración SIEM;
- alertas email/webhook.

### Fase 4 - UI

- dashboard web;
- filtros;
- vista por seed;
- vista por finding;
- timeline;
- severidad;
- evidencias;
- exportación de informes.
