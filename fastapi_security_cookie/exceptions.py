from fastapi import HTTPException, status


class InvalidSession(HTTPException):
    def __init__(self, detail: any = 'Invalid or Expire Session', headers: dict[str, any] | None = None):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
        self.headers = headers
