# 🛡️ EBMPrivatyScan

> **Sistema automatizado de diagnóstico de privacidad y ciberseguridad para sitios web**, diseñado específicamente para verificar el cumplimiento de la **Ley N° 21.719** en Chile.

---

## 📋 Descripción del Proyecto
**EBMPrivatyScan** es una herramienta desarrollada para la empresa **ADMI** como parte del proyecto integrado de la carrera de Ingeniería en Informática / Analista Programador en **INACAP**. 

La plataforma automatiza la inspección de la superficie web de PyMEs y empresas, evaluando componentes críticos exigidos por la normativa de protección de datos personales (Ley N° 21.719), tales como encriptación HTTPS, gestión de cookies, formularios de consentimiento y canales de atención.

---

## 🚀 Características Principales

* **Inspección SSL/HTTPS**: Verificación de certificados de seguridad válidos y encriptación en tránsito.
* **Escaneo DOM con Playwright**: Análisis automatizado de la interfaz visible para detectar:
  * Banners de consentimiento de cookies.
  * Formularios de contacto y validación de casillas de verificación (*checkboxes* de privacidad).
  * Canales de mensajería (botones flotantes de WhatsApp).
  * Enlaces a Políticas de Privacidad y avisos legales.
* **Motor de Cálculo de Riesgo**: Ponderación dinámica del nivel de vulnerabilidad del sitio web.
* **Persistencia e Historial (Panel ADMI)**: Almacenamiento automático de cada auditoría en base de datos SQLite con un panel administrativo para consultar registros anteriores.
* **Generador de Informes PDF**: Exportación de reportes formales y profesionales listos para ser entregados al cliente.
* **Dockerizado**: Entorno listo para producción y despliegue rápido mediante Docker y Docker Compose.

---

## 🛠️ Tecnologías Utilizadas

* **Backend**: Python 3.10+, FastAPI, SQLAlchemy, SQLite, Playwright (Async).
* **Generación de Documentos**: ReportLab (PDF).
* **Frontend**: HTML5, Tailwind CSS, JavaScript (Vanilla).
* **Despliegue**: Docker, Docker Compose.

## 🚀 Ejecución local

Desde la raíz del proyecto, inicia el backend y el frontend con Docker Compose:

```bash
docker compose -f backend/docker-compose.yml up --build
```

Abre `http://localhost:8080` para usar la interfaz. Nginx sirve el frontend y reenvía las rutas `/api/` al backend, que solo es accesible dentro de la red interna de Docker. Para detener y retirar los contenedores:

```bash
docker compose -f backend/docker-compose.yml down
```

La base de datos SQLite se guarda en `sql_app.db` en la raíz del proyecto.

### Compartir el prototipo con Dev Tunnels

1. Inicia los servicios con el comando Docker Compose anterior y verifica que la interfaz cargue en `http://localhost:8080`.
2. En VS Code, reenvía el puerto `8080` desde la vista **Ports** y comparte la URL HTTPS del túnel con acceso **privado**, solo para participantes invitados.
3. Las solicitudes del navegador usan rutas relativas (`/api/...`), por lo que pasan por el mismo túnel y Nginx las reenvía al backend. El backend no publica un puerto en el host; no configures un túnel separado para él.
4. Cierra el túnel y detén los servicios al terminar las pruebas.

El prototipo no implementa autenticación ni separación del historial por usuario. Aunque el túnel se configure como privado, compártelo solo con personas de confianza y pide analizar únicamente sitios para los que el equipo tenga autorización. No uses datos personales ni consideres este montaje como un despliegue de producción.

---

## 📂 Estructura del Repositorio

```text
EBMPrivatyScan/
├── .gitignore
├── backend/
│   ├── .dockerignore
│   ├── app/
│   │   ├── models/          # Modelos de base de datos (SQLAlchemy)
│   │   ├── services/        # Motores de análisis DOM (Playwright) y PDF
│   │   ├── database.py      # Configuración de SQLite
│   │   └── main.py          # Punto de entrada de FastAPI
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── requirements.txt
├── frontend/
│   └── index.html           # Interfaz gráfica (Evaluador y Panel ADMI)
├── sql_app.db               # Base de datos local (no se versiona)
└── README.md                # Documentación del proyecto