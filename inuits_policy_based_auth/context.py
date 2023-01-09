class Context:
    """
    A class containing data about the context of a request.

    The data provided in this class is used in policies to determine whether a user is authenticated/authorized.

    Attributes
    ----------
    _resource_scope : str
        a scope a user must have for accessing a protected resource when policies rely on scope-based authorization
    _http_request : Unknown
        an HTTP request that is used by policies to determine access to a resource.
    """

    def __init__(self, resource_scope, http_request):
        """
        Parameters
        ----------
        resource_scope : str
            a scope a user must have for accessing a protected resource when policies rely on scope-based authorization
        http_request : Unknown
            an HTTP request that is used by policies to determine access to a resource.
        """

        self._resource_scope = resource_scope
        self._http_request = http_request

    @property
    def resource_scope(self):
        return self._resource_scope

    @property
    def http_request(self):
        return self._http_request
