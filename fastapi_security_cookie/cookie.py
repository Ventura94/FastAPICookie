from uuid import UUID

from fastapi import Response, Request
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security.base import SecurityBase
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .exceptions import InvalidSession
from .schemas import CookieParameters


class SessionCookie(SecurityBase):
    def __init__(self, *, cookie_name: str, identifier: str, secret_key: str,
                 cookie_params: CookieParameters = CookieParameters(),
                 scheme_name: str | None = None):
        self.model: APIKey = APIKey(**{"in": APIKeyIn.cookie}, name=cookie_name)
        self._identifier = identifier
        self.scheme_name = scheme_name or self.__class__.__name__
        self.signer = URLSafeTimedSerializer(secret_key, salt=cookie_name)
        self.cookie_params = cookie_params

    @property
    def identifier(self) -> str:
        return self._identifier

    def decoded_signer_session(self, signed_session_id) -> UUID:
        return UUID(self.signer.loads(signed_session_id, max_age=self.cookie_params.max_age, return_timestamp=False))

    def __call__(self, request: Request, response: Response) -> UUID:
        signed_session_id = request.cookies.get(self.model.name)
        if not signed_session_id:
            raise InvalidSession("No Session Provider")
        try:
            session_id = self.decoded_signer_session(signed_session_id)
        except (SignatureExpired, BadSignature):
            self.delete_from_response(response)
            raise InvalidSession()
        self.attach_id_state(request, session_id)
        return session_id

    def delete_from_response(self, response: Response) -> None:
        if self.cookie_params.domain:
            response.delete_cookie(key=self.model.name, path=self.cookie_params.path, domain=self.cookie_params.domain)
        else:
            response.delete_cookie(key=self.model.name, path=self.cookie_params.path)

    def attach_to_response(self, response: Response, session_id: UUID) -> None:
        response.set_cookie(key=self.model.name, value=str(self.signer.dumps(session_id.hex)),
                            **dict(self.cookie_params))

    def attach_id_state(self, request: Request, session_id: UUID) -> None:
        request.state.session_id = {self.identifier: session_id}
