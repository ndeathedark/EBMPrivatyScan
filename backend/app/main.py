import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .database import SessionLocal, init_db
from .routers import audits, auth
from .security import CSRF_HEADER, CSRF_VALUE
from .services.retention import purge_expired

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ebm")

MAX_BODY_BYTES = 16 * 1024
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


async def _retention_loop() -> None:
    while True:
        try:
            with SessionLocal() as db:
                purge_expired(db)
        except Exception:  # noqa: BLE001 - la tarea periódica nunca debe detener la API
            logger.exception("Error en la tarea de retención")
        await asyncio.sleep(3600)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    task = asyncio.create_task(_retention_loop())
    yield
    task.cancel()


app = FastAPI(
    title="EBMPrivatyScan API",
    description="Diagnóstico preliminar de evidencias de privacidad web (Ley N° 21.719).",
    version="2.0.0",
    lifespan=lifespan,
    # La documentación interactiva solo se publica fuera de producción.
    docs_url=None if settings.is_production else "/api/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/api/openapi.json",
)

if settings.allowed_origins:
    # CORS restringido: solo orígenes, métodos y encabezados explícitos.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "X-Requested-With", "X-Audit-Token"],
    )


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # 1) Límite de tamaño del cuerpo: la API solo recibe JSON pequeños.
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "La solicitud es demasiado grande."}, status_code=413)

    # 2) Protección CSRF: las operaciones que modifican estado exigen un encabezado
    #    personalizado que un sitio externo no puede enviar sin una preflight CORS.
    if request.method in UNSAFE_METHODS and request.url.path.startswith("/api/"):
        if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            return JSONResponse({"detail": "Solicitud rechazada (falta el encabezado de protección CSRF)."},
                                status_code=403)

    response = await call_next(request)

    # 3) Encabezados de seguridad para las respuestas de la API.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    if not request.url.path.startswith("/api/docs"):
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(_request: Request, exc: RequestValidationError):
    messages = []
    for err in exc.errors():
        field = ".".join(str(p) for p in err.get("loc", []) if p != "body")
        msg = err.get("msg", "valor inválido")
        if field == "url":
            msg = "La URL no tiene un formato válido. Ejemplo: https://tudominio.cl"
        messages.append(msg)
    return JSONResponse({"detail": " ".join(dict.fromkeys(messages)) or "Datos inválidos."}, status_code=422)


@app.exception_handler(Exception)
async def unhandled_handler(_request: Request, exc: Exception):
    # No se exponen trazas ni detalles internos al cliente.
    logger.exception("Error no controlado: %s", exc.__class__.__name__)
    return JSONResponse({"detail": "Ocurrió un error interno. Intenta nuevamente."}, status_code=500)


@app.get("/api/v1/health")
def health():
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(audits.router)
