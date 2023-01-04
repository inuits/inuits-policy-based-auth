from collections.abc import MutableMapping


class UserAuthData:
    def __init__(self, *, auth_object):
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

    def __flatten_auth_data_generator(self, data: MutableMapping, parent_key):
        for key, value in data.items():
            flattened_key = parent_key + "." + key if parent_key else key
            if isinstance(value, MutableMapping):
                yield from self.flatten_auth_data(value, flattened_key).items()
            else:
                yield flattened_key, value

    def flatten_auth_data(self, data: MutableMapping, parent_key=""):
        return dict(self.__flatten_auth_data_generator(data, parent_key))
