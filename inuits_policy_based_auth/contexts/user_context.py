from collections.abc import MutableMapping


class UserContext:
    """
    A class containing data about the authenticated user.

    Attributes
    ----------
    _auth_objects : list[Unknown]
        the objects used to authenticate a user, for example a token
    _email : str
        the email of the authenticated user
    _roles : list[str]
        the roles of the authenticated user
    _scopes : list[str]
        the scopes of the authenticated user

    Methods
    -------
    flatten_auth_object(data, parent_key)
        flattens the auth object to be a dict of one level deep
    """

    def __init__(self):
        self._auth_objects = []
        self._email = ""
        self._roles = []
        self._scopes = []

    @property
    def auth_objects(self):
        return self._auth_objects

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, email: str):
        self._email = email

    @property
    def roles(self):
        return self._roles

    @roles.setter
    def roles(self, roles: list[str]):
        self._roles = roles

    @property
    def scopes(self):
        return self._scopes

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
            an object used to authenticate a user with, for example a token
        parent_key : str, optional
            a key that will be the root key

        Returns
        -------
        dict[Unknown, Unknown]
            the flattened auth object
        """

        return dict(self.__flatten_auth_object_generator(data, parent_key))
