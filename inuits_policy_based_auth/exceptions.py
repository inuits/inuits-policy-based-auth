class PolicyFactoryException(Exception):
    def __init__(self, message):
        super().__init__(message)


class NoUserContextException(PolicyFactoryException):
    def __init__(self):
        super().__init__(
            "Cannot get an object of type UserContext if no policies are applied yet."
        )


class NoAuthenticationPoliciesToApplyException(PolicyFactoryException):
    def __init__(self):
        super().__init__("No authentication policies set to apply.")


class NoAuthorizationPoliciesToApplyException(PolicyFactoryException):
    def __init__(self):
        super().__init__("No authorization policies set to apply.")


class InvalidFallbackKey(PolicyFactoryException):
    def __init__(self, key: str):
        super().__init__(
            f"Provided fallback key '{key}' is not registered in either authentication policies, authorization policies, or both."
        )


class NoFallbackKeySet(PolicyFactoryException):
    def __init__(self):
        super().__init__("No fallback key for policy mapping is set.")


class PolicyException(Exception):
    pass


class AuthenticateMethodDidNotReturnObjectOfTypeUserContextException(PolicyException):
    def __init__(self):
        super().__init__(
            "Authenticate method of authentication policy did not return an object of type UserContext."
        )


class AuthorizeMethodDidNotReturnObjectOfTypePolicyContextException(PolicyException):
    def __init__(self):
        super().__init__(
            "Authorize method of authorization policy did not return an object of type PolicyContext."
        )
