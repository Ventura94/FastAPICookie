from enum import StrEnum


class SameSiteEnum(StrEnum):
    lax = "lax"
    strict = "strict"
    none = "none"
