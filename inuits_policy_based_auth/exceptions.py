class PolicyFactoryException(Exception):
    def __init__(self, message):
        super().__init__(message)


class NoStrategySetForAuthenticatorException(PolicyFactoryException):
    def __init__(self):
        super().__init__(
            "No concrete implementation (strategy) set for Authenticator to authenticate with."
        )


class NoPoliciesToApplyException(PolicyFactoryException):
    def __init__(self):
        super().__init__(
            "No policies set to apply in app.py, or in app_list.json under '{app}.security.policies'."
        )


class NoUserAuthDataException(PolicyFactoryException):
    def __init__(self):
        super().__init__(
            "Cannot get an object of type UserAuthData when no policies were applied."
        )


class PolicyException(Exception):
    pass


class AuthenticateMethodDidNotReturnObjectOfTypeUserAuthData(PolicyException):
    def __init__(self):
        super().__init__(
            "The authenticate method of a policy or an authentication strategy did not return an object of type UserAuthData."
        )
