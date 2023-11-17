class AccessRestrictions:
    """
    A class containing properties used to restrict access.

    The value of the properties of this class are defined by authorization
    policies, and provides the ability to do attribute based access control
    (abac).

    Properties
    ----------
    filters : Unknown
        Object used to filter on attributes of documents.
    post_request_hook : (response: Unknown, *args: Unknown, **kwargs: Unknown) -> Unknown
        Function used to manipulate response data of a request.
    """

    def __init__(self):
        self._filters = None
        self._post_request_hook = lambda response, *args, **kwargs: response

    @property
    def filters(self):
        """Object used to filter on attributes of documents."""

        return self._filters

    @filters.setter
    def filters(self, filters):
        self._filters = filters

    @property
    def post_request_hook(self):
        """Function used to manipulate response data of a request."""

        return self._post_request_hook

    @post_request_hook.setter
    def post_request_hook(self, post_request_hook):
        self._post_request_hook = post_request_hook
