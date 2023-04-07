import logging
import fnmatch
from spaceone.core import pygrpc
from spaceone.core import utils
from spaceone.core.transaction import Transaction
from spaceone.core.handler import BaseAuthorizationHandler
from spaceone.core.error import ERROR_HANDLER_CONFIGURATION, ERROR_PERMISSION_DENIED

_LOGGER = logging.getLogger(__name__)


class AuthorizationGRPCHandler(BaseAuthorizationHandler):

    def __init__(self, transaction: Transaction, config):
        super().__init__(transaction, config)
        self._initialize()

    def _initialize(self):
        if 'uri' not in self.config:
            _LOGGER.error(f'[_initialize] uri config is undefined.')
            raise ERROR_HANDLER_CONFIGURATION(handler='AuthenticationGRPCHandler')

        try:
            uri_info = utils.parse_grpc_uri(self.config['uri'])
        except Exception as e:
            _LOGGER.error(f'[_initialize] AuthenticationGRPCHandler Init Error: {e}')
            raise ERROR_HANDLER_CONFIGURATION(handler='AuthenticationGRPCHandler')

        self.grpc_method = pygrpc.get_grpc_method(uri_info)

    def verify(self, params=None):
        self._check_permissions()

        user_type = self.transaction.get_meta('authorization.user_type')
        scope = self.transaction.get_meta('authorization.scope', 'DOMAIN')

        if user_type == 'DOMAIN_OWNER':
            self._verify_domain_owner(params)
        else:
            self._verify_auth(params, scope)

    def _check_permissions(self):
        permissions = self.transaction.get_meta('authorization.permissions')
        if isinstance(permissions, list):
            for permission in permissions:
                request_api = f'{self.transaction.service}.{self.transaction.resource}.{self.transaction.verb}'
                if fnmatch.fnmatch(request_api, permission):
                    return True

            raise ERROR_PERMISSION_DENIED()

        return True

    def _verify_domain_owner(self, params):
        # Pass all methods
        self.transaction.set_meta('authorization.role_type', 'DOMAIN')

    def _verify_auth(self, params, scope):
        project_id_key = self.transaction.get_meta('authorization.project_id', 'project_id')
        project_group_id_key = self.transaction.get_meta('authorization.project_group_id', 'project_group_id')
        user_id_key = self.transaction.get_meta('authorization.user_id', 'user_id')
        require_project_group_id = self.transaction.get_meta('authorization.require_project_group_id', False)
        require_project_id = self.transaction.get_meta('authorization.require_project_id', False)
        require_user_id = self.transaction.get_meta('authorization.require_user_id', False)
        require_domain_id = self.transaction.get_meta('authorization.require_domain_id', False)

        print(f"----")
        print(f"grpc_method: {self.grpc_method}")
        print(f"project_id_key: {project_id_key}")
        print(f"project_group_id_key: {project_group_id_key}")
        print(f"user_id_key: {user_id_key}")
        print(f"require_project_group_id: {require_project_group_id}")
        print(f"require_project_id: {require_project_id}")
        print(f"require_user_id: {require_user_id}")
        print(f"require_domain_id: {require_domain_id}")
        print("------")

        try:
            response = self.grpc_method(
                {
                    'service': self.transaction.service,
                    'resource': self.transaction.resource,
                    'verb': self.transaction.verb,
                    'scope': scope,
                    'domain_id': params.get('domain_id'),
                    'project_id': params.get(project_id_key),
                    'project_group_id': params.get(project_group_id_key),
                    'user_id': params.get(user_id_key),
                    'require_project_id': require_project_id,
                    'require_project_group_id': require_project_group_id,
                    'require_user_id': require_user_id,
                    'require_domain_id': require_domain_id
                },
                metadata=self.transaction.get_connection_meta()
            )

            projects = list(response.projects)
            project_groups = list(response.project_groups)

            self.transaction.set_meta('authorization.role_type', response.role_type)
            self.transaction.set_meta('authorization.projects', projects)
            self.transaction.set_meta('authorization.project_groups', project_groups)
        except Exception as e:
            _LOGGER.error(f'[_verify_auth] Authorization.verify request failed: {e}')
            raise ERROR_PERMISSION_DENIED()
