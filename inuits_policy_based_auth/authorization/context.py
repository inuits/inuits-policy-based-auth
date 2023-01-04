class Context:
    def __init__(self, resource_scope, http_request):
        self._resource_scope = resource_scope
        self._http_request = http_request

    @property
    def resource_scope(self):
        return self._resource_scope

    @property
    def http_request(self):
        return self._http_request
