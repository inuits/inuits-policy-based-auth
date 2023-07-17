import base64
import json
import requests

from abc import ABC
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.jose import jwt
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7523 import JWTBearerToken
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
    role_scope_mapping_filepath : str, optional
        Path to a JSON file containing a mapping of scopes to their corresponding roles.
    static_issuer : str, optional
        A string representing the issuer of the JWT. This parameter is required
        if remote token validation is not enabled.
    static_public_key : str, optional
        A string representing the public key used to verify the signature of the
        JWT. This parameter is required if remote token validation is not enabled.
    allowed_issuers : List[str], optional
        A list of token issuers whose tokens are allowed. If this parameter is not
        passed or the list is empty, all issuers are allowed.
    **kwargs : dict
        Any additional keyword arguments to be passed to the JWTValidator constructor.
    """

    def __init__(
        self,
        logger: Logger,
        role_scope_mapping_filepath=None,
        static_issuer=None,
        static_public_key=None,
        allowed_issuers=None,
        **kwargs,
    ):
        validator = JWTValidator(
            logger,
            static_issuer,
            static_public_key,
            allowed_issuers,
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
        A string representing the issuer of the JWT. This parameter is required
        if remote token validation is not enabled.
    static_public_key : str, optional
        A string representing the public key used to verify the signature of the
        JWT. This parameter is required if remote token validation is not enabled.
    allowed_issuers : List[str], optional
        A list of token issuers whose tokens are allowed. If this parameter is not
        passed or the list is empty, all issuers are allowed.
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
    __get_issuer_from_token_string(token_string: str) -> Optional[str]:
        Extracts the issuer from a JWT token without verifying the signature.

    __get_jwks_from_issuer(issuer: str) -> dict:
        Retrieves JWKS from the issuer to be used to validate the token.
    """

    TOKEN_TYPE = "bearer"
    token_cls = JWTBearerToken

    def __init__(
        self,
        logger,
        static_issuer,
        static_public_key,
        allowed_issuers,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.logger = logger
        self.static_issuer = static_issuer
        self.static_public_key = static_public_key
        self.allowed_issuers = allowed_issuers
        self.claims_options = {
            "exp": {"essential": True},
            "azp": {"essential": True},
            "sub": {"essential": True},
        }
        self.jwks_cache = {}

    def __decode_token(self, token_string, jwks):
        try:
            claims = jwt.decode(
                token_string,
                jwks,
                claims_options=self.claims_options,
                claims_cls=self.token_cls,
            )
            claims.validate()
            return claims
        except:
            return None

    def __get_jwks(self, issuer):
        if issuer == self.static_issuer:
            jwks = f"-----BEGIN PUBLIC KEY-----\n{self.static_public_key}\n-----END PUBLIC KEY-----"
        elif issuer in self.jwks_cache and self.jwks_cache[issuer] is not None:
            jwks = self.jwks_cache[issuer]
        else:
            jwks = self.__get_jwks_from_issuer(issuer)
            self.jwks_cache[issuer] = jwks
        return jwks

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
        try:
            issuer = self.__get_issuer_from_token_string(token_string)
            if not self.allowed_issuers:
                self.logger.warning(
                    "No allowed issuers configured, allowing all issuers!"
                )
            elif issuer not in self.allowed_issuers:
                raise Exception(f"Issuer {issuer} not allowed")
            jwks = self.__get_jwks(issuer)
            token = self.__decode_token(token_string, jwks)
            if not token:
                self.jwks_cache[issuer] = None
                jwks = self.__get_jwks(issuer)
                token = self.__decode_token(token_string, jwks)
            return token
        except Exception as ex:
            self.logger.error(f"Could not get decoded & validated token: {ex}")
            return None

    @staticmethod
    def __get_issuer_from_token_string(token_string):
        # Adding "=="  is necessary for correct base64 padding
        payload = f'{token_string.split(".")[1]}=='
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
        return decoded.get("iss")

    @staticmethod
    def __get_jwks_from_issuer(issuer):
        req = requests.get(f"{issuer}/.well-known/openid-configuration")
        if req.status_code != 200:
            raise Exception(
                f"Failed to get issuer's OpenID configuration: {req.text.strip()}"
            )
        jwks_url = req.json()["jwks_uri"]
        req = requests.get(jwks_url)
        if req.status_code != 200:
            raise Exception(f"Failed to get issuer's JWKS: {req.text.strip()}")
        return req.json()["keys"]
