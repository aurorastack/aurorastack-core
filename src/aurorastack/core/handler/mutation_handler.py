import logging
from aurorastack.core.handler import BaseMutationHandler

_LOGGER = logging.getLogger(__name__)


class AuroraStackMutationHandler(BaseMutationHandler):
    def request(self, params):
        user_role_type: str = self.transaction.get_meta("authorization.role_type")
        tenant_id: str = self.transaction.get_meta("authorization.tenant_id")
        workspace_id: str = self.transaction.get_meta("authorization.workspace_id")
        user_projects: list = self.transaction.get_meta("authorization.projects")
        user_id: str = self.transaction.get_meta("authorization.user_id")
        set_user_id: str = self.transaction.get_meta("authorization.set_user_id")

        if user_role_type == "SYSTEM_TOKEN":
            if tenant_id:
                params["tenant_id"] = tenant_id

            if workspace_id:
                params["workspace_id"] = workspace_id

        elif user_role_type == "TENANT_ADMIN":
            params["tenant_id"] = tenant_id
        elif user_role_type == "WORKSPACE_OWNER":
            params["tenant_id"] = tenant_id
            params["workspace_id"] = workspace_id
        elif user_role_type == "WORKSPACE_MEMBER":
            params["tenant_id"] = tenant_id
            params["workspace_id"] = workspace_id
            params["user_projects"] = user_projects
        elif user_role_type == "USER":
            params["tenant_id"] = tenant_id

        if set_user_id:
            params["user_id"] = user_id

        return params
