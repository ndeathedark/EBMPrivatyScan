# Registro de mejoras — EBMPrivatyScan v2.0

Cada cambio indica qué se hizo y por qué, con referencia al informe (requerimientos y sección 14.1).

## 1. Errores que impedían o falseaban el funcionamiento

| Cambio | Por qué |
|---|---|
| `requirements.txt` regenerado con hashes SHA-256 | El Dockerfile usaba `--require-hashes`, pero el archivo no tenía hashes: `docker compose up --build` fallaba al instalar dependencias. |
| `check_same_thread` solo se pasa a SQLite | Se enviaba a cualquier motor; con PostgreSQL (arquitectura objetivo) la conexión fallaba. |
| `PRAGMA foreign_keys=ON` en SQLite | SQLite ignora las claves foráneas por defecto; sin esto, borrar un usuario dejaría auditorías huérfanas. |
| El PDF usa la fecha de la auditoría | Mostraba la fecha en que se descargaba, no la del análisis (RF12 exige la fecha del diagnóstico). |
| Se quitó el emoji del PDF | Helvetica no tiene ese glifo y se veía como cuadros. |
| DNS y TLS se ejecutan fuera del bucle async | `getaddrinfo` y el socket TLS bloqueaban el servidor completo mientras duraban. |
| Un error de conexión TLS ya no se informa como “sin HTTPS” | Un timeout se calificaba FAIL “no utiliza HTTPS”, contradiciendo el criterio de RF03; ahora es `NO_CONCLUYENTE`. |
| Tener un formulario ya no da “PASS” | Detectar un formulario no es un cumplimiento; ahora se evalúa qué datos pide y qué informa. |
| Banner ausente sin rastreadores ya no penaliza | Era un falso positivo: si no hay cookies opcionales, el banner puede no ser necesario. |

## 2. Seguridad

| Cambio | Por qué |
|---|---|
| Validación de **cada redirección** en la navegación | `page.route` de Playwright no intercepta los saltos de redirección: un sitio público podía redirigir al navegador hacia `169.254.169.254` (metadatos de la nube) o a la red interna (SSRF). Ahora cada salto se resuelve con `route.fetch(max_redirects=0)` y se valida antes de seguirlo. |
| TLS conecta a la IP ya validada y Chromium fija esa IP (`--host-resolver-rules`) | Antes se volvía a resolver el DNS después de validar, lo que permite *DNS rebinding* (validar una IP pública y conectar a una privada). |
| Solo puertos 80/443/8080/8443; bloqueo de hosts sin dominio, `.lan`, `.corp`, IPv4 mapeadas en IPv6, CGNAT | Evita usar la herramienta para escanear servicios arbitrarios (SSH, bases de datos) o rangos internos. |
| Service workers bloqueados, descargas deshabilitadas, tope de 600 solicitudes, sin media/websockets, diálogos descartados | Los service workers evaden el filtro de rutas; los demás límites acotan consumo y superficie de ataque del navegador. |
| Historial privado con autenticación; vista global solo para administradores (con registro) | `GET /history` devolvía todas las auditorías a cualquiera: era la amenaza “Acceso indebido al historial” de la sección 14.1. |
| Informes de invitado protegidos con token aleatorio (se guarda solo su hash) | Con IDs secuenciales cualquiera podía descargar `/audit/1/pdf`, `/audit/2/pdf`… (IDOR). Ahora sin permiso la respuesta es 404, igual que si no existiera. |
| Contraseñas con scrypt + sal, política de contraseñas, tiempo constante, mensajes genéricos | Impide leer contraseñas si se filtra la base y dificulta enumerar cuentas. |
| Sesión en cookie `HttpOnly` + `SameSite=Strict` (+ `Secure` en HTTPS) | El token no es accesible desde JavaScript (mitiga robo por XSS) ni se envía desde otros sitios. |
| Encabezado anti-CSRF obligatorio en POST/DELETE | Un sitio externo no puede enviar ese encabezado sin una preflight CORS, que no se permite. |
| Límites de tasa (análisis, login, registro, correo) en la API y en Nginx | Cada análisis lanza un Chromium: sin límites, unas pocas solicitudes saturaban el servidor; también frena fuerza bruta en el login. |
| Máximo de análisis simultáneos y tiempo máximo total (504 explícito) | Protege memoria/CPU y cumple RNF02: un tiempo agotado se comunica como tal, no como éxito. |
| Límite de 16 KB por solicitud; errores internos sin trazas; `/docs` oculto en producción | Reduce DoS y fuga de información técnica. |
| CSP estricta y encabezados (X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP); `server_tokens off` | Bloquea XSS, clickjacking y filtración de URLs por Referer. |
| `X-Forwarded-Proto` ya no copia el valor del cliente; `X-Real-IP` lo fija Nginx | El cliente podía falsificar esos encabezados. |
| Se eliminó Tailwind desde CDN y los `onclick` en línea | Un script de terceros podía ejecutar cualquier código en la página (cadena de suministro), impedía una CSP estricta y enviaba la IP de los visitantes a un tercero, justo lo que la herramienta señala en otros sitios. El informe ya lo indicaba como pendiente (sección 12). |
| Docker: usuario sin privilegios, sistema de archivos de solo lectura, `cap_drop: ALL`, `no-new-privileges`, límites de memoria/CPU/procesos, Nginx *unprivileged*, healthcheck | El navegador procesa contenido no confiable; si se compromete, el daño queda contenido. |
| El código ya no se monta desde el host | `..:/workspace` montaba todo el repositorio (incluido `.git`) con escritura dentro del contenedor. Ahora solo se monta un volumen de datos. |
| Dependencias actualizadas y auditadas con `pip-audit` (0 vulnerabilidades conocidas) | FastAPI 0.110 dependía de una versión de Starlette con avisos de seguridad; PyJWT también se fijó en una versión sin avisos. |
| Configuración y secretos por variables de entorno (`.env.example`); validaciones en producción | Exigencia de RNF04 y de la sección 4.3 (credenciales fuera del código). En producción no arranca sin `SECRET_KEY` y `COOKIE_SECURE`. |
| CORS cerrado por defecto y configurable con orígenes, métodos y encabezados explícitos | Amenaza “Configuración web permisiva” (14.1). |
| Declaración obligatoria de autorización para analizar un sitio | El informe limita el uso a sitios autorizados; ahora queda explícito en la interfaz y en la API. |
| User-Agent que identifica a la herramienta | Antes se hacía pasar por un navegador Windows; identificarse es coherente con la transparencia ética (sección 7). |

## 3. Funcionalidad según los requerimientos

| Cambio | Requerimiento |
|---|---|
| Rastreadores y cookies de seguimiento **antes** del consentimiento | RF04, RF08 |
| Pulsa “Rechazar” y comprueba si los rastreadores se detienen | RF04 (interacción definida, sin enviar formularios: RNF03) |
| Lista documentada y versionada de patrones de terceros (`trackers.py`) | RF08 (alcance limitado visible en el informe) |
| Banner: distingue aceptar / rechazar / configurar y plataformas CMP conocidas | RF04 |
| Formularios: campos personales, casillas premarcadas, envío por http, excluye buscadores | RF05 |
| WhatsApp: busca aviso visible sobre las conversaciones | RF06 |
| Política: se lee su contenido; extrae fecha, organización, RUT, contacto, derechos y si cita la Ley 21.719 o solo la 19.628 | RF07 |
| Estados `CUMPLE`, `BRECHA`, `ALERTA`, `NO_CONCLUYENTE`, `NO_APLICA`, `INFORMATIVO`, con severidad, evidencia y limitación | RF09 |
| Explicaciones neutrales (“conviene revisar”) en vez de afirmaciones categóricas | RF10, sección 7 |
| Indicador ponderado y documentado sobre las comprobaciones aplicables | RF02, RF11 |
| PDF con evidencia, limitaciones y nota de alcance | RF12 |
| Envío por correo (SMTP configurable) con confirmación solo tras éxito | RF13 |
| Registro, inicio de sesión, historial privado y rol administrador | RF14, HU04, HU05 |
| Modelo normalizado USUARIO–AUDITORÍA–HALLAZGO | Sección 13 |
| Retención automática (24 h invitados, 180 días cuentas), eliminar análisis y eliminar cuenta | Sección 14 (conservación y eliminación); derecho de supresión |
| Política de privacidad propia de la plataforma (`privacidad.html`) | Sección 14 (Prod); coherencia con lo que se exige a otros |
| 32 pruebas automatizadas y CI en GitHub Actions | Sección 10.2 indicaba que no había pruebas |

## 4. Interfaz

Diseño propio sin dependencias externas, modo oscuro, adaptable a móvil (la tabla del historial se reorganiza
en pantallas estrechas), enlace para saltar al contenido, foco visible, mensajes en regiones `aria-live`,
respeto de “reducir movimiento”, errores en la página en lugar de `alert()`, y descarga del PDF por `fetch`
para no exponer el token en la URL.

## 5. Pendiente y no verificado

- El flujo real con Chromium no se pudo ejecutar en el entorno donde se hicieron los cambios (sin navegador
  disponible); las pruebas simulan el navegador. Debe probarse en el contenedor con sitios autorizados,
  especialmente el manejo de redirecciones.
- Firewall de salida para el backend (bloquear rangos privados y metadatos), HTTPS real, Redis para límites
  compartidos, PostgreSQL con respaldos, revisión legal de textos y pruebas con usuarios.
- El indicador cambió de fórmula: los porcentajes del informe (p. ej., 45 % de admi.cl) deben recalcularse.
