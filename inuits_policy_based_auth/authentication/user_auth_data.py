from collections.abc import MutableMapping


class UserAuthData:
    """
    A class containing data about the authenticated user.

    Attributes
    ----------
    _auth_object : Unknown
        the object used to authenticate a user, for example a token
    _email : str
        the email of the authenticated user
    _roles : list[str]
        the roles of the authenticated user
    _permissions : list[str]
        the permissions of the authenticated user

    Methods
    -------
    flatten_auth_object(data, parent_key)
        flattens the auth object to be a dict of one level deep
    """

    def __init__(self, *, auth_object):
        """
        Parameters
        ----------
        auth_object : Unknown
            the object used to authenticate a user with, for example a token
        """

        self._auth_object = auth_object
        self._email = ""
        self._roles = []
        self._permissions = []

    @property
    def auth_object(self):
        self._auth_object

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
    def permissions(self):
        return self._permissions

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
