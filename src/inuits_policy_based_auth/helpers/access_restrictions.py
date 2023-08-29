class AccessRestrictions:
    """
    A class containing properties used to restrict access.

    The value of the properties of this class are defined by authorization
    policies, and provides the ability to do attribute based access control
    (abac).

    Properties
    ----------
    filters : dict
        Key-value pairs used to filter on attributes of documents.
    """

    def __init__(self):
        self._filters = {}

    @property
    def filters(self):
        """Key-value pairs used to filter on attributes of documents."""

        return self._filters

    @filters.setter
    def filters(self, filters: dict):
        self._filters = filters
