class RequestContext:
    """
    A class containing data about the context of a request.

    The data provided in this class is used in policies to determine whether a user is authenticated/authorized.

    Attributes
    ----------
    _http_request : Unknown
        an HTTP request that is used by policies to determine access to a resource
    _resource_scope : str, optional
        a scope a user must have for accessing a protected resource when policies rely on scope-based authorization
    """

    def __init__(self, http_request, resource_scope=""):
        """
        Parameters
        ----------
        http_request : Unknown
            an HTTP request that is used by policies to determine access to a resource.
        resource_scope : str, optional
            a scope a user must have for accessing a protected resource when policies rely on scope-based authorization
        """

        self._http_request = http_request
        self._resource_scope = resource_scope

    @property
    def http_request(self):
        return self._http_request

    @property
    def resource_scope(self):
        return self._resource_scope
