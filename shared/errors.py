import logging
import sqlite3

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException


def install_handlers(app: FastAPI):
    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, headers=exc.headers,
                            content={"status": "error", "message": str(exc.detail)})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        errors = [{"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content={
            "status": "error", "message": "Request validation failed", "errors": errors})

    @app.exception_handler(sqlite3.Error)
    async def database_error(request: Request, exc: sqlite3.Error):
        logging.getLogger(__name__).exception("Database operation failed")
        return JSONResponse(status_code=503, content={
            "status": "error", "message": "Database temporarily unavailable"})

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        logging.getLogger(__name__).exception("Unexpected service error")
        return JSONResponse(status_code=500, content={
            "status": "error", "message": "An unexpected service error occurred"})
