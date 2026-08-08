from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from app.logging.logger import logger

async def http_exception_handler(
    request: Request,
    exc: HTTPException,
):

    logger.warning(
        "%s %s -> %s",
        request.method,
        request.url.path,
        exc.detail,
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": {
                "code": exc.status_code,
                "type": "HTTPException",
                "message": exc.detail,
            },
        },
    )

async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):

    logger.warning(
        "Validation error on %s",
        request.url.path,
    )

    return JSONResponse(
        status_code=422,
        content={
            "success": False,
            "error": {
                "code": 422,
                "type": "ValidationError",
                "message": exc.errors(),
            },
        },
    )

async def database_exception_handler(
    request: Request,
    exc: SQLAlchemyError,
):

    logger.exception(exc)

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": 500,
                "type": "DatabaseError",
                "message": "Database operation failed.",
            },
        },
    )

async def global_exception_handler(
    request: Request,
    exc: Exception,
):
    logger.exception(exc)

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {
                "code": 500,
                "type": "InternalServerError",
                "message": "Unexpected server error.",
            },
        },
    )

