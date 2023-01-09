class PolicyFactoryException(Exception):
    def __init__(self, message):
        super().__init__(message)


class NoAuthorizationPoliciesToApplyException(PolicyFactoryException):
    def __init__(self):
        super().__init__("No authorization policies set to apply.")


class NoUserContextException(PolicyFactoryException):
    def __init__(self):
        super().__init__(
            "Cannot get an object of type UserContext if no policies are applied yet."
        )


class PolicyException(Exception):
    pass


class AuthenticateMethodDidNotReturnObjectOfTypeUserContextException(PolicyException):
    def __init__(self):
        super().__init__(
            "Authenticate method of authentication policy did not return an object of type UserContext."
        )


class NoRequestContextInAuthorizationPolicyException(PolicyException):
    def __init__(self):
        super().__init__("No request_context in authorization policy.")
