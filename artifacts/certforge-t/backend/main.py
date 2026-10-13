from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from api_errors import WorkbenchError
from crypto_operations import openssl_version
from routers.certificates import router as certificates_router
from routers.pkcs12 import router as pkcs12_router
from schemas import HealthResponse

API_PREFIX = "/certforge-api"

app = FastAPI(
    title="CertForge_t API",
    version="1.0.0",
    description="Self-hosted certificate inspection and conversion operations.",
    docs_url=f"{API_PREFIX}/docs",
    openapi_url=f"{API_PREFIX}/openapi.json",
    redoc_url=None,
)


@app.exception_handler(WorkbenchError)
async def workbench_error_handler(_, exc: WorkbenchError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_, __: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Provide the required files and supported options.",
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(_, exc: StarletteHTTPException) -> JSONResponse:
    message = (
        exc.detail
        if isinstance(exc.detail, str)
        else "The requested operation could not be completed."
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": "http_error", "message": message}},
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(_, __: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_error",
                "message": "The operation could not be completed.",
            }
        },
    )


@app.get(f"{API_PREFIX}/health", response_model=HealthResponse)
def health() -> HealthResponse:
    try:
        version = openssl_version()
    except WorkbenchError:
        return HealthResponse(status="degraded", openssl_version="unavailable")
    return HealthResponse(status="healthy", openssl_version=version)


app.include_router(certificates_router)
app.include_router(pkcs12_router)
