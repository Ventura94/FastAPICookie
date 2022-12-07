from pydantic import BaseModel

from fastapi_security_cookie.enums import SameSiteEnum


class CookieParameters(BaseModel):
    max_age: int = 14 * 24 * 60 * 60  # 14 days in seconds
    path: str = "/"
    domain: str | None = None
    secure: bool = False
    httponly: bool = True
    samesite: SameSiteEnum = "lax"
