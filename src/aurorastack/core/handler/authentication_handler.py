import json
import logging

from aurorastack.core import cache, config
from aurorastack.core.connector.aurora_connector import AuroraConnector
from aurorastack.core.auth.jwt import JWTAuthenticator, JWTUtil
from aurorastack.core.transaction import get_transaction
from aurorastack.core.handler import BaseAuthenticationHandler
from aurorastack.core.error import ERROR_AUTHENTICATE_FAILURE

_LOGGER = logging.getLogger(__name__)


class AuroraStackAuthenticationHandler(BaseAuthenticationHandler):
    def __init__(self, handler_config):
        super().__init__(handler_config)
        self.identity_client = None
        self._initialize()

    def _initialize(self) -> None:
        self.identity_conn: AuroraConnector = AuroraConnector(service="identity")

    def verify(self, params: dict) -> None:
        token = self._get_token()
        tenant_id = self._extract_tenant_id(token)

        token_info = self._authenticate(token, tenant_id)

        if token_info.get("typ") == "SYSTEM_TOKEN":
            self._update_system_meta(token_info)
        else:
            version = token_info.get("ver")
            if version not in ["2.0"]:
                raise ERROR_AUTHENTICATE_FAILURE(message="invalid token version.")

            owner_type = token_info.get("own")
            if owner_type == "APP":
                client_id = token_info.get("jti")
                tenant_id = token_info.get("did")
                token_info["permissions"] = self._check_app(client_id, tenant_id)

            self._update_meta(token_info)

    @cache.cacheable(key="handler:authentication:{tenant_id}:public-key", alias="local")
    def _get_public_key(self, tenant_id: str) -> str:
        system_token = config.get_global("TOKEN")

        _LOGGER.debug(f"[_get_public_key] get jwk from identity service: {tenant_id}")
        response = self.identity_conn.dispatch(
            "Tenant.get_public_key", {"tenant_id": tenant_id}, token=system_token
        )

        return response["public_key"]

    @cache.cacheable(
        key="handler:authentication:{tenant_id}:client:{client_id}", alias="local"
    )
    def _check_app(self, client_id, tenant_id) -> list:
        system_token = config.get_global("TOKEN")

        _LOGGER.debug(f"[_check_app] check app from identity service: {client_id}")
        response = self.identity_conn.dispatch(
            "App.check",
            {
                "client_id": client_id,
                "tenant_id": tenant_id,
            },
            token=system_token,
        )

        return response.get("permissions", [])

    def _authenticate(self, token: str, tenant_id: str) -> dict:
        public_key = self._get_public_key(tenant_id)
        return JWTAuthenticator(json.loads(public_key)).validate(token)

    @staticmethod
    def _get_token() -> str:
        transaction = get_transaction()
        token = transaction.meta.get("token")
        if not isinstance(token, str) or len(token) == 0:
            raise ERROR_AUTHENTICATE_FAILURE(message="empty token provided.")

        return token

    @staticmethod
    def _extract_tenant_id(token):
        try:
            decoded = JWTUtil.unverified_decode(token)
        except Exception:
            _LOGGER.debug(f"[_extract_tenant_id] failed to decode token: {token[:10]}")
            raise ERROR_AUTHENTICATE_FAILURE(message="failed to decode token.")

        if tenant_id := decoded.get("did"):
            return tenant_id
        else:
            raise ERROR_AUTHENTICATE_FAILURE(message="empty tenant_id provided.")

    def _update_meta(self, token_info: dict) -> None:
        """
        Args:
            token_info(dict): {
                'iss': 'str',   # issuer (aurorastack.identity)
                'rol': 'str',   # role type
                'typ': 'str',   # token type (ACCESS_TOKEN | REFRESH_TOKEN | CLIENT_SECRET)
                'own': 'str',   # owner (USER | APP)
                'did': 'str',   # tenant_id
                'wid': 'str',   # workspace_id, Optional
                'aud': 'str',   # audience (user_id | app_id)
                'exp': 'int',   # expiration time
                'iat': 'int',   # issued at
                'jti': 'str',   # jwt id (token_key | client_id), Optional
                'permissions': 'list',  # permissions, Optional
                'ver': 'str',   # jwt version
        """

        token_type = token_info.get("typ")
        role_type = token_info.get("rol")
        owner_type = token_info.get("own")
        audience = token_info.get("aud")
        tenant_id = token_info.get("did")
        workspace_id = token_info.get("wid")
        permissions = token_info.get("permissions")
        projects = token_info.get("projects")

        self.transaction.set_meta("authorization.token_type", token_type)
        self.transaction.set_meta("authorization.role_type", role_type)
        self.transaction.set_meta("authorization.owner_type", owner_type)
        self.transaction.set_meta("authorization.tenant_id", tenant_id)
        self.transaction.set_meta("authorization.audience", audience)
        self.transaction.set_meta("authorization.workspace_id", workspace_id)
        self.transaction.set_meta("authorization.permissions", permissions)
        self.transaction.set_meta("authorization.projects", projects)

        if owner_type == "USER":
            self.transaction.set_meta("authorization.user_id", audience)
        elif owner_type == "APP":
            self.transaction.set_meta("authorization.app_id", audience)

    def _update_system_meta(self, token_info: dict) -> None:
        """
        Args:
            token_info(dict): {
                'iss': 'str',   # issuer (aurorastack.identity)
                'typ': 'str',   # token type (SYSTEM_TOKEN)
                'own': 'str',   # owner (SYSTEM)
                'did': 'str',   # tenant_id (tenant-root)
                'aud': 'str',   # audience (root_tenant_user_id)
                'iat': 'int',   # issued at
                'jti': 'str',   # jwt id
                'ver': 'str',   # jwt version
        """

        token_type = token_info.get("typ")
        owner_type = token_info.get("own")
        audience = token_info.get("aud")
        tenant_id = self.transaction.get_meta("x_tenant_id")
        workspace_id = self.transaction.get_meta("x_workspace_id")

        self.transaction.set_meta("authorization.token_type", token_type)
        self.transaction.set_meta("authorization.role_type", "SYSTEM_TOKEN")
        self.transaction.set_meta("authorization.owner_type", owner_type)
        self.transaction.set_meta("authorization.tenant_id", tenant_id)
        self.transaction.set_meta("authorization.audience", audience)
        self.transaction.set_meta("authorization.workspace_id", workspace_id)
