from collections.abc import MutableMapping
from inuits_policy_based_auth.helpers.immutable_dict import ImmutableDict


class UserContext:
    """
    A class containing data about the authenticated user.

    Properties
    ----------
    auth_objects : ImmutableDict
        An immutable dict containing objects used to authenticate a user,
        for example a token.
    email : str
        The email of the authenticated user.
    roles : list[str]
        The roles of the authenticated user.
    scopes : list[str]
        The scopes of the authenticated user.
    tenant_names : list[str]
        Names of the tenants the authenticated user is part of.
    tenant_objects : list[str]
        Object representations of the tenants the authenticated user is part of.

    Methods
    -------
    flatten_auth_object(data, parent_key)
        Flattens the auth object to be a dict of one level deep.
    """

    def __init__(self):
        self._auth_objects = ImmutableDict({})
        self._email = ""
        self._roles = []
        self._scopes = []
        self._tenant_names = []
        self._tenant_objects = []

    @property
    def auth_objects(self):
        """
        An immutable dict containing objects used to authenticate a user,
        for example a token.
        """

        return self._auth_objects

    @property
    def email(self):
        """The email of the authenticated user."""

        return self._email

    @email.setter
    def email(self, email: str):
        self._email = email

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
    def tenant_names(self):
        """Names of the tenants the authenticated user is part of."""

        return self._tenant_names

    @tenant_names.setter
    def tenant_names(self, names: list[str]):
        self._tenant_names = names

    @property
    def tenant_objects(self):
        """
        Object representations of the tenants the authenticated user is part of.
        """

        return self._tenant_objects

    @tenant_objects.setter
    def tenant_objects(self, objects: list):
        self._tenant_objects = objects

    def __flatten_auth_object_generator(self, data: MutableMapping, parent_key):
        for key, value in data.items():
            flattened_key = parent_key + "." + key if parent_key else key
            if isinstance(value, MutableMapping):
                yield from self.flatten_auth_object(value, flattened_key).items()
            else:
                yield flattened_key, value

    def flatten_auth_object(self, data: MutableMapping, parent_key=""):
        """Flattens the auth object to be a dict of one level deep.

        Parameters
        ----------
        data : MutableMapping
            An object used to authenticate a user with, for example a token.
        parent_key : str, optional
            A key that will be the root key for the flattened dict.

        Returns
        -------
        dict
            A flattened dictionary representation of the auth object.
        """

        return dict(self.__flatten_auth_object_generator(data, parent_key))
