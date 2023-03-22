import inspect


class ImmutableDict:
    """
    A dictionary-like object that cannot be modified after initialization.

    The keys and values of an ImmutableDict can be any hashable object.
    Values can also be dictionaries or lists containing hashable objects.

    This class can be used to create read-only dictionaries that cannot be
    accidentally modified, as well as for creating immutable configurations
    or objects that need to be serialized.
    """

    def __init__(self, data):
        """
        Initialize an ImmutableDict object with a dictionary or mapping object.

        Parameters
        ----------
        data : dict-like
            A dictionary or mapping object to initialize the ImmutableDict with.

        Returns
        -------
        ImmutableDict
            An ImmutableDict object with the initial data.

        Raises
        ------
        TypeError
            If the input data is not a dictionary or mapping object.
        """

        self._data = {}
        self._add_initial_data(data)

    def get(self, key):
        """
        Get the value associated with a key.

        Parameters
        ----------
        key : hashable
            The key to get the value for.

        Returns
        -------
        hashable or None
            The value associated with the key, or None if the key is not found.
        """
        return self._data.get(key)

    def add_key_value_pair(self, key, value):
        """
        Add a new key-value pair to the ImmutableDict.

        Parameters
        ----------
        key : hashable
            The key of the new key-value pair.
        value : hashable
            The value of the new key-value pair.

        Raises
        ------
        TypeError
            If the ImmutableDict is modified.
        """

        if key in self._data:
            raise TypeError("Cannot modify immutable dict")

        self._data[key] = value

    def __getitem__(self, key):
        """
        Get the value associated with a key.

        Parameters
        ----------
        key : hashable
            The key to get the value for.

        Returns
        -------
        hashable
            The value associated with the key.

        Raises
        ------
        KeyError
            If the key is not found in the ImmutableDict.
        """

        return self._data[key]

    def __setitem__(self, key, value):
        """
        Raise a TypeError if the ImmutableDict is modified.

        Raises
        ------
        TypeError
            If the ImmutableDict is modified.
        """

        if inspect.stack()[1][0].f_locals.get("self") is not self:
            raise TypeError("Cannot modify immutable dict")

        self._data[key] = value

    def __delitem__(self, _):
        """
        Raise a TypeError if the ImmutableDict is modified.

        Raises
        ------
        TypeError
            If the ImmutableDict is modified.
        """

        raise TypeError("Cannot modify immutable dict")

    def __repr__(self):
        """
        Get the string representation of the ImmutableDict.

        Returns
        -------
        str
            The string representation of the ImmutableDict.
        """

        return str(self._data)

    def _add_initial_data(self, data):
        """
        Recursively add the initial data to the ImmutableDict.

        Parameters
        ----------
        data : dict-like
            A dictionary or mapping object to add to the ImmutableDict.
        """

        try:
            for key, value in data.items():
                if isinstance(value, dict):
                    self._data[key] = ImmutableDict(value)
                elif isinstance(value, list):
                    self._data[key] = ImmutableDict._freeze_list(value)
                else:
                    self._data[key] = value
        except AttributeError:
            raise TypeError(f"{data} is not a dict-like object")

    @staticmethod
    def _freeze_list(list_to_be_frozen):
        """
        Recursively freeze a list of hashable objects.

        Parameters
        ----------
        list_to_be_frozen : list
            The list to be frozen.

        Returns
        -------
        tuple
            A tuple representing the frozen list, with all nested lists and dictionaries
            recursively frozen as well.
        """
        frozen_list = []

        for item in list_to_be_frozen:
            if isinstance(item, dict):
                frozen_list.append(ImmutableDict(item))
            elif isinstance(item, list):
                frozen_list.append(ImmutableDict._freeze_list(item))
            else:
                frozen_list.append(item)

        return tuple(frozen_list)
