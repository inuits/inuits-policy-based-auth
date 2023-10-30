class RequestContext:
    """A class containing data about the context of a request.

    The data provided in this class is used in policies to determine whether a
    user is authenticated/authorized.

    Properties
    ----------
    http_request : Unknown
        An HTTP request used by policies to determine access to a resource.
    resource_scopes : list[str], optional
        Scopes a user must have for accessing a protected resource when policies
        rely on scope-based authorization.
    """

    def __init__(self, http_request, resource_scopes: list[str] = None):
        """
        Parameters
        ----------
        http_request : Unknown
            An HTTP request used by policies to determine access to a resource.
        resource_scopes : list[str], optional
            Scopes a user must have for accessing a protected resource when policies
            rely on scope-based authorization.
        """

        self._http_request = http_request
        self._resource_scopes = resource_scopes if resource_scopes else []

    @property
    def http_request(self):
        """
        An HTTP request used by policies to determine access to a resource.
        """

        return self._http_request

    @property
    def resource_scopes(self):
        """
        Scopes a user must have for accessing a protected resource when policies
        rely on scope-based authorization.
        """

        return self._resource_scopes

    def _serialize(self) -> dict:
        return {
            "http_request": {
                "method": self._http_request.method,
                "path": self._http_request.path,
                "headers": self._http_request.headers,
                "data": self._http_request.data,
            }
        }

    def __hash__(self) -> int:
        return hash(str(self._serialize()))

    def __eq__(self, request_context) -> bool:
        return self.__hash__() == request_context.__hash__()

    def __ne__(self, request_context) -> bool:
        return not self.__eq__(request_context)
