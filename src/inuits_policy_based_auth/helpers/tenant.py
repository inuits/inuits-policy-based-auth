class Tenant:
    """
    A class containing user data in the context of a specific tenant.

    Properties
    ----------
    id : str
        Id of the tenant the authenticated user is part of.
    roles : list[str]
        The roles of the authenticated user.
    scopes : list[str]
        The scopes of the authenticated user.
    raw : dict
        Raw object representation of the tenant the authenticated user is part of.
    """

    def __init__(self):
        self._id = ""
        self._roles = []
        self._scopes = []
        self._raw = {}

    @property
    def id(self):
        """Id of the tenant the authenticated user is part of."""

        return self._id

    @id.setter
    def id(self, id: str):
        self._id = id

    @property
    def roles(self):
        """The roles of the authenticated user."""

        return self._roles

    @roles.setter
    def roles(self, roles: list[str]):
        self._roles = roles

    @property
    def scopes(self):
        """The scopes of the authenticated user."""

        return self._scopes

    @scopes.setter
    def scopes(self, scopes: list[str]):
        self._scopes = scopes

    @property
    def raw(self):
        """
        Raw object representation of the tenant the authenticated user is part of.
        """

        return self._raw

    @raw.setter
    def raw(self, raw: dict):
        self._raw = raw
