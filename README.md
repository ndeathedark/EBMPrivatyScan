# EBMPrivatyScan

Diagnóstico **automatizado y preliminar** de la evidencia de privacidad visible en sitios web públicos,
orientado a la **Ley N° 21.719** (Chile). Proyecto Integrado de Analista Programador (INACAP) para ADMI.

> El informe describe lo que se observa desde un navegador. No es certificación de cumplimiento ni asesoría
> jurídica, y puede tener falsos positivos o negativos.

## Qué revisa

| Comprobación | Evidencia que recopila |
|---|---|
| HTTPS (RF03) | Conexión TLS en 443, validez del certificado, versión TLS, vencimiento, URL final y HSTS |
| Banner de cookies (RF04) | Presencia, botones aceptar / rechazar / configurar, plataforma CMP conocida |
| Rastreadores antes del consentimiento (RF04, RF08) | Solicitudes a proveedores de una lista documentada y cookies de seguimiento durante la carga inicial |
| Respeto del rechazo (RF04) | Pulsa “Rechazar” (única interacción) y observa si siguen cargándose rastreadores |
| Formularios (RF05) | Campos personales, casillas de consentimiento y si vienen marcadas, información visible, envío sin cifrar |
| WhatsApp (RF06) | Enlaces/botones y aviso visible sobre el tratamiento de las conversaciones |
| Política de privacidad (RF07) | Enlace, lectura del contenido: fecha, organización, derechos, contacto, mención de Ley 21.719 o 19.628 |
| Recursos de terceros | Dominios externos contactados (informativo) |

Cada hallazgo tiene estado (`CUMPLE`, `BRECHA`, `ALERTA`, `NO_CONCLUYENTE`, `NO_APLICA`, `INFORMATIVO`),
severidad, evidencia, explicación en lenguaje simple y limitación. El indicador de riesgo es
`Σ(peso × factor) / Σ(pesos aplicables)`; los pesos están documentados en `backend/app/services/rules.py`.

## Arquitectura

```text
Navegador ──► Nginx (frontend estático + CSP + límites) ──► FastAPI ──► Chromium headless (Playwright)
                                                              │
                                                              └─► SQLite (por defecto) / PostgreSQL
```

```text
backend/
├── app/
│   ├── config.py            # Configuración por variables de entorno
│   ├── security.py          # Contraseñas (scrypt), sesión JWT en cookie HttpOnly, permisos, límites
│   ├── database.py          # Motor SQLAlchemy (SQLite/PostgreSQL)
│   ├── cli.py               # Crear administradores
│   ├── models/audit.py      # USUARIO 1—N AUDITORIA 1—N HALLAZGO
│   ├── routers/             # auth.py (cuentas) y audits.py (análisis, historial, PDF, correo)
│   └── services/            # url_guard (anti-SSRF), tls_check, dom_inspector, trackers, rules,
│                            # pdf_generator, mailer, retention
├── tests/                   # Pruebas automatizadas (pytest)
├── nginx/                   # Configuración del proxy
├── Dockerfile · docker-compose.yml · requirements.in/.txt · .env.example
frontend/
├── index.html · app.js · styles.css   # Sin CDN ni scripts en línea
└── privacidad.html                    # Política de privacidad de la propia plataforma
```

## Ejecución con Docker

Requiere Docker Compose v2.24 o superior.

```bash
cp backend/.env.example backend/.env          # opcional: completar SECRET_KEY, SMTP, etc.
docker compose -f backend/docker-compose.yml up --build
```

Abrir `http://localhost:8080`. La base de datos se guarda en el volumen `ebm_data`.

Crear un administrador:

```bash
docker compose -f backend/docker-compose.yml exec backend python -m app.cli create-admin correo@admi.cl
```

> **Actualización desde la versión anterior:** el esquema cambió (usuarios y hallazgos normalizados).
> Si existe un `sql_app.db` antiguo, respáldalo y elimínalo; la API se niega a iniciar con el esquema viejo.

## Pruebas

```bash
cd backend
pip install --require-hashes -r requirements.txt
pip install -r requirements-dev.txt
python -m pytest -q
pip-audit -r requirements.txt --require-hashes
```

Las pruebas simulan el navegador y la conexión TLS; el análisis real con Chromium debe validarse en el
contenedor con sitios autorizados.

## Seguridad: resumen

- Anti-SSRF: solo http/https, puertos 80/443/8080/8443, sin credenciales en la URL, solo IP públicas;
  validación de **cada salto de redirección** y de cada recurso; IP del host fijada en Chromium; service workers bloqueados.
- Cuentas: contraseñas con scrypt, política de contraseñas, respuestas que no revelan cuentas, límite de intentos.
- Sesión en cookie `HttpOnly` + `SameSite=Strict` (+ `Secure` con HTTPS) y encabezado anti-CSRF obligatorio.
- Historial privado por cuenta; acceso a informes de invitado solo con token aleatorio (no por ID secuencial).
- Retención automática (24 h invitados, 180 días cuentas), eliminación de análisis y de cuenta.
- CSP estricta, encabezados de seguridad, límites de tamaño y de tasa en Nginx y en la API.
- Contenedores sin root, sistema de archivos de solo lectura, sin capacidades, con límites de memoria y procesos.
- Dependencias fijadas con hashes y auditadas con `pip-audit` (también en CI).

### Pendiente antes de producción

- Reglas de **salida de red** (firewall/egress) para el contenedor del backend que bloqueen rangos privados y
  metadatos de la nube: es la defensa definitiva contra SSRF y DNS rebinding.
- HTTPS real, `APP_ENV=production`, `COOKIE_SECURE=true`, HSTS, WAF/CDN.
- Limitador de tasa compartido (Redis) si hay más de una réplica; PostgreSQL con respaldos cifrados.
- Revisión legal de `privacidad.html` y de los textos de los hallazgos; pruebas con usuarios.
