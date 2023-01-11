class FakeHttpRequest:
    def __init__(self):
        self._request_type = ""

    @property
    def method(self):
        return self._request_type
