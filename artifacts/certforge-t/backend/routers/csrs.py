from fastapi import APIRouter
from starlette.concurrency import run_in_threadpool

from creation_operations import generate_csr
from schemas import GenerateCsrRequest, GeneratedCsrResponse

router = APIRouter(prefix="/certforge-api/csrs", tags=["csrs"])


@router.post("/generate", response_model=GeneratedCsrResponse)
async def create_csr(request: GenerateCsrRequest) -> GeneratedCsrResponse:
    return await run_in_threadpool(generate_csr, request)
