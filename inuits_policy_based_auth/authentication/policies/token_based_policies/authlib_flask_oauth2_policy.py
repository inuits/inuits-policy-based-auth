import base64
import json
import requests

from abc import ABC
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.jose import jwt
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7523 import JWTBearerToken
from datetime import datetime
from inuits_policy_based_auth.authentication.base_authentication_policy import (
    BaseAuthenticationPolicy,
)
from werkzeug.exceptions import Unauthorized


class AuthlibFlaskOauth2Policy(BaseAuthenticationPolicy):
    """
    An authentication policy that uses Authlib Flask OAuth2 to do token-based authentication.
    """

    def __init__(
        self,
        logger,
        static_issuer=None,
        static_public_key=None,
        realms=None,
        role_permission_file_location=None,
        remote_token_validation=False,
        remote_public_key=None,
        realm_cache_sync_time=1800,
        **extra_attributes,
    ):
        validator = JWTValidator(
            logger,
            static_issuer,
            static_public_key,
            realms,
            remote_token_validation,
            remote_public_key,
            realm_cache_sync_time,
            **extra_attributes,
        )
        resource_protector = ResourceProtector()
        resource_protector.register_token_validator(validator)
        self._resource_protector = resource_protector

        self._logger = logger
        self._role_permission_mapping = self.__load_role_permission_file(
            role_permission_file_location
        )

    def authenticate(self, user_context):
        try:
            token = self._resource_protector.acquire_token()
            user_context.auth_objects.add_key_value_pair("token", token)
            flattened_token = user_context.flatten_auth_object(token)

            user_context.email = flattened_token.get("email", "")
            user_context.roles = flattened_token.get(
                f"resource_access.{token['azp']}.roles", []
            )
            if self._role_permission_mapping:
                for role in user_context.roles:
                    try:
                        user_context.scopes.extend(self._role_permission_mapping[role])
                    except KeyError:
                        continue

            return user_context
        except OAuth2Error as error:
            raise Unauthorized(str(error))

    def __load_role_permission_file(self, role_permission_file_location):
        try:
            with open(role_permission_file_location, "r") as role_permission_file:
                return json.load(role_permission_file)
        except IOError:
            self._logger.error(
                f"Could not read role_permission file: {role_permission_file_location}"
            )
        except json.JSONDecodeError:
            self._logger.error(
                f"Invalid json in role_permission file: {role_permission_file_location}"
            )


class JWTValidator(BearerTokenValidator, ABC):
    TOKEN_TYPE = "bearer"
    token_cls = JWTBearerToken

    def __init__(
        self,
        logger,
        static_issuer=None,
        static_public_key=None,
        realms=None,
        remote_token_validation=False,
        remote_public_key=None,
        realm_cache_sync_time=1800,
        **extra_attributes,
    ):
        super().__init__(**extra_attributes)
        self.logger = logger
        self.static_issuer = static_issuer
        self.static_public_key = static_public_key
        self.realms = realms if realms else []
        self.remote_token_validation = remote_token_validation
        self.remote_public_key = remote_public_key
        self.realm_cache_sync_time = realm_cache_sync_time
        self.realm_config_cache = {}
        self.claims_options = {
            "exp": {"essential": True},
            "azp": {"essential": True},
            "sub": {"essential": True},
        }

    def authenticate_token(self, token_string):
        issuer = self.__get_unverified_issuer(token_string)
        if not issuer:
            return None

        realm_config = self.__get_realm_config_by_issuer(issuer)
        public_key = ""
        if "public_key" in realm_config:
            public_key = f'-----BEGIN PUBLIC KEY-----\n{realm_config["public_key"]}\n-----END PUBLIC KEY-----'

        try:
            claims = jwt.decode(
                token_string,
                public_key,
                claims_options=self.claims_options,
                claims_cls=self.token_cls,
            )
            claims.validate()

            if self.remote_token_validation:
                result = requests.get(
                    f"{issuer}/protocol/openid-connect/userinfo",
                    headers={"Authorization": f"Bearer {token_string}"},
                )
                if result.status_code != 200:
                    raise Exception(result.content.strip())

            return claims
        except Exception as error:
            self.logger.error(f"Authenticate token failed: {error}")
            return None

    def __get_realm_config_by_issuer(self, issuer):
        if issuer == self.static_issuer:
            return {"public_key": self.static_public_key}
        if issuer not in self.realms:
            return {}
        if self.remote_public_key:
            return {"public_key": self.remote_public_key}

        current_time = datetime.timestamp(datetime.now())
        if (
            issuer in self.realm_config_cache
            and current_time - self.realm_config_cache[issuer]["last_sync_time"]
            < self.realm_cache_sync_time
        ):
            return self.realm_config_cache[issuer]

        self.realm_config_cache[issuer] = requests.get(issuer).json()
        self.realm_config_cache[issuer]["last_sync_time"] = current_time
        return self.realm_config_cache[issuer]

    @staticmethod
    def __get_unverified_issuer(token_string):
        try:
            # Adding "=="  is necessary for correct base64 padding
            payload = f'{token_string.split(".")[1]}=='
        except:
            return None

        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
        if "iss" in decoded:
            return decoded["iss"]

        return None
