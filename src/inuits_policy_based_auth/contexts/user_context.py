from collections.abc import MutableMapping
from inuits_policy_based_auth.helpers.access_restrictions import AccessRestrictions
from inuits_policy_based_auth.helpers.immutable_dict import ImmutableDict
from inuits_policy_based_auth.helpers.tenant import Tenant


class UserContext:
    """
    A class containing data about the authenticated user.

    Properties
    ----------
    auth_objects : ImmutableDict
        An immutable dict containing objects used to authenticate a user,
        for example a token.
    id : str
        The id of the authenticated user.
    email : str
        The email of the authenticated user.
    preferred_username : str
        The preferred_username of the authenticated user.
    x_tenant : Tenant
        The user tenant that is requested from the X-Tenant-Id http header.
    tenants : list[Tenant]
        All tenants that are related to the user.
    bag : dict
        Dict that can contain any kind of information. It enables the possibility
        to share values dynamically between policies themselves or between
        policies and the api.
    access_restrictions : AccessRestrictions
        A class containing properties used to restrict access.

    Methods
    -------
    flatten_auth_object(data, parent_key)
        Flattens the auth object to be a dict of one level deep.
    """

    def __init__(self):
        self._auth_objects = ImmutableDict({})
        self._id = ""
        self._email = ""
        self._preferred_username = ""
        self._x_tenant = Tenant()
        self._tenants: list[Tenant] = []
        self._bag = {}
        self._access_restrictions = AccessRestrictions()

    @property
    def auth_objects(self):
        """
        An immutable dict containing objects used to authenticate a user,
        for example a token.
        """

        return self._auth_objects

    @property
    def id(self):
        """The id of the authenticated user."""

        return self._id

    @id.setter
    def id(self, id: str):
        self._id = id

    @property
    def email(self):
        """The email of the authenticated user."""

        return self._email

    @email.setter
    def email(self, email: str):
        self._email = email

    @property
    def preferred_username(self):
        """The preferred_username of the authenticated user."""

        return self._preferred_username

    @preferred_username.setter
    def preferred_username(self, preferred_username: str):
        self._preferred_username = preferred_username

    @property
    def x_tenant(self):
        """The user tenant that is requested from the X-Tenant-Id http header."""

        return self._x_tenant

    @x_tenant.setter
    def x_tenant(self, x_tenant: Tenant):
        self._x_tenant = x_tenant

    @property
    def tenants(self):
        """All tenants that are related to the user."""

        return self._tenants

    @tenants.setter
    def tenants(self, tenants: list[Tenant]):
        self._tenants = tenants

    @property
    def bag(self):
        """
        Dict that can contain any kind of information. It enables the possibility
        to share values dynamically between policies themselves or between
        policies and the api.
        """

        return self._bag

    @bag.setter
    def bag(self, bag: dict):
        self._bag = bag

    @property
    def access_restrictions(self):
        """A class containing properties used to restrict access."""

        return self._access_restrictions

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
