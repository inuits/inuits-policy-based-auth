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
from logging import Logger
from werkzeug.exceptions import Unauthorized


class AuthlibFlaskOauth2Policy(BaseAuthenticationPolicy):
    """
    An authentication policy that uses Authlib Flask OAuth2 to do token-based
    authentication.

    Parameters:
    -----------
    logger : Logger
        Logger object for logging authentication events and errors.
    static_issuer : str, optional
        A string representing the issuer of the JWT. This parameter is required
        if remote token validation is not enabled.
    static_public_key : str, optional
        A string representing the public key used to verify the signature of the
        JWT. This parameter is required if remote token validation is not enabled.
    realms : List[str], optional
        A list of realm names that the JWT must belong to in order to be accepted.
    role_scope_mapping_filepath : str, optional
        Path to a JSON file containing a mapping of scopes to their corresponding roles.
    remote_token_validation : bool, optional
        A flag indicating whether token validation should be done remotely.
    remote_public_key : str, optional
        A string representing the public key of the authorization server used for
        remote token validation.
    realm_cache_sync_time : int, optional
        The number of seconds after which the realm cache should be refreshed.
    **kwargs : dict
        Any additional keyword arguments to be passed to the JWTValidator constructor.
    """

    def __init__(
        self,
        logger: Logger,
        static_issuer=None,
        static_public_key=None,
        realms=None,
        role_scope_mapping_filepath=None,
        remote_token_validation=False,
        remote_public_key=None,
        realm_cache_sync_time=1800,
        **kwargs,
    ):
        validator = JWTValidator(
            logger,
            static_issuer,
            static_public_key,
            realms,
            remote_token_validation,
            remote_public_key,
            realm_cache_sync_time,
            **kwargs,
        )
        resource_protector = ResourceProtector()
        resource_protector.register_token_validator(validator)
        self._resource_protector = resource_protector

        self._logger = logger
        self._role_scope_mapping = self.__load_role_scope_mapping(
            role_scope_mapping_filepath
        )

    def authenticate(self, user_context):
        """
        Authenticate the user based on the token in the user context.

        Parameters:
        -----------
        user_context : UserContext
            The context of the user requesting authentication.

        Returns:
        --------
        UserContext
            The user context with the authenticated user details added.

        Raises:
        -------
        Unauthorized
            If the authentication fails.
        """

        try:
            token = self._resource_protector.acquire_token()
            user_context.auth_objects.add_key_value_pair("token", token)
            flattened_token = user_context.flatten_auth_object(token)

            user_context.email = flattened_token.get("email", "")
            user_context.roles = flattened_token.get(
                f"resource_access.{token['azp']}.roles", []
            )
            if self._role_scope_mapping:
                for role in user_context.roles:
                    try:
                        user_context.scopes.extend(self._role_scope_mapping[role])
                    except KeyError:
                        continue

            return user_context
        except OAuth2Error as error:
            raise Unauthorized(str(error))

    def __load_role_scope_mapping(self, file):
        try:
            with open(file, "r") as role_scope_mapping:
                return json.load(role_scope_mapping)
        except IOError:
            self._logger.error(f"Could not read role_scope_mapping: {file}")
        except json.JSONDecodeError:
            self._logger.error(f"Invalid json in role_scope_mapping: {file}")


class JWTValidator(BearerTokenValidator, ABC):
    """
    Validator for JSON Web Tokens (JWT).

    This class inherits from BearerTokenValidator and validates tokens of type "bearer".
    It also has the ability to perform remote token validation by checking against an
    OpenID Connect provider.

    Parameters:
    -----------
    logger : Logger
        An instance of a logger object to be used for logging.
    static_issuer : str, optional
        A string representing the static issuer of the JWT. If provided, it will be used
        to validate the "iss" claim in the JWT.
    static_public_key : str, optional
        A string representing the static public key used to verify the JWT signature. If
        provided, it will be used instead of the public key provided by the issuer.
    realms : List[str], optional
        A list of realm names to use for validating the JWT.
    remote_token_validation : bool, optional
        A boolean indicating whether remote token validation should be performed. If True,
        the validator will check the token against the userinfo endpoint of an OpenID
        Connect provider.
    remote_public_key : str, optional
        A string representing the public key used by the remote OpenID Connect provider to
        verify the JWT signature. If provided, it will be used instead of the public key
        provided by the issuer.
    realm_cache_sync_time : int, optional
        An integer representing the number of seconds to cache realm configuration data
        before syncing with the issuer.
    **kwargs : dict
        Additional keyword arguments to be passed to the parent class.

    Attributes:
    -----------
    TOKEN_TYPE : str
        A string representing the token type that this validator is responsible for.
        Always "bearer".
    token_cls : type
        A class representing the type of token that this validator is responsible for.
        Always JWTBearerToken.
    claims_options : dict
        A dictionary representing the claims options to be used for validating the JWT.
        By default, this dictionary contains options for the "exp", "azp", and "sub" claims.

    Methods:
    --------
    authenticate_token(token_string: str) -> Optional[JWTBearerToken]:
        Authenticates a JWT token and returns a JWTBearerToken object if successful. If
        authentication fails, None is returned.

    Private Methods:
    ----------------
    __get_unverified_issuer(token_string: str) -> Optional[str]:
        Extracts the issuer from a JWT token without verifying the signature.

    __get_realm_config_by_issuer(issuer: str) -> dict:
        Retrieves realm configuration data from the issuer and caches it for future use.
    """

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
        **kwargs,
    ):
        super().__init__(**kwargs)
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
        """
        Authenticate a JWT token and return a JWTBearerToken object if successful.

        Parameters:
        -----------
        token_string : str
            A string representing the JWT token to be authenticated.

        Returns:
        --------
        Optional[JWTBearerToken]
            If authentication is successful, returns a JWTBearerToken object containing
            the decoded JWT claims. If authentication fails, None is returned.
        """

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
