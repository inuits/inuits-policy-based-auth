import pytest

from inuits_policy_based_auth.helpers.immutable_dict import ImmutableDict


class TestImmutableDict:
    def setup_method(self):
        self.data = {"key1": "value1", "key2": {"inner_key1": "inner_value1"}}

    def test_init(self):
        immutable_dict = ImmutableDict(self.data)
        assert str(immutable_dict._data) == str(self.data)

    def test_init_raises_TypeError_if_not_dict_like(self):
        with pytest.raises(TypeError):
            ImmutableDict("not a dict-like object")

    def test_get_existing_key(self):
        immutable_dict = ImmutableDict(self.data)
        result = immutable_dict.get("key1")
        assert result is not None

    def test_get_non_existing_key(self):
        immutable_dict = ImmutableDict(self.data)
        result = immutable_dict.get("non_existent_key")
        assert result is None

    def test_add_key_value_pair(self):
        immutable_dict = ImmutableDict(self.data)

        immutable_dict.add_key_value_pair("key3", "value3")

        assert str(immutable_dict._data) == str(
            {"key1": "value1", "key2": {"inner_key1": "inner_value1"}, "key3": "value3"}
        )
        assert str(immutable_dict._data) != str(self.data)

    def test_add_key_value_pair_raises_TypeError_if_modified(self):
        immutable_dict = ImmutableDict(self.data)
        with pytest.raises(TypeError):
            immutable_dict.add_key_value_pair("key2", "value2")

    def test_getitem(self):
        immutable_dict = ImmutableDict(self.data)
        assert immutable_dict["key1"] == "value1"
        assert immutable_dict["key2"]["inner_key1"] == "inner_value1"

    def test_getitem_raises_KeyError_if_key_not_found(self):
        immutable_dict = ImmutableDict(self.data)
        with pytest.raises(KeyError):
            immutable_dict["non_existent_key"]

    def test_setitem_raises_TypeError_if_modified(self):
        immutable_dict = ImmutableDict(self.data)
        with pytest.raises(TypeError):
            immutable_dict["key1"] = "new_value"

    def test_delitem_raises_TypeError_if_modified(self):
        immutable_dict = ImmutableDict(self.data)
        with pytest.raises(TypeError):
            del immutable_dict["key"]

    def test_immutable_dict_has_string_representation(self):
        immutable_dict = ImmutableDict(self.data)
        assert repr(immutable_dict) == str(self.data)

    def test_initial_data_is_added_recursively(self):
        data = {
            "key1": "value1",
            "key2": {"key3": "value3", "key4": [1, 2, {"key5": "value5"}]},
        }

        immutable_dict = ImmutableDict(data)

        assert immutable_dict["key1"] == "value1"
        assert immutable_dict["key2"]["key3"] == "value3"
        assert immutable_dict["key2"]["key4"][2]["key5"] == "value5"
        with pytest.raises(TypeError):
            ImmutableDict(1234)

    def test_empty_list(self):
        assert ImmutableDict._freeze_list([]) == tuple()

    def test_frozen_list(self):
        items = [1, 2, 3, {"a": 4, "b": [5, 6]}]

        frozen_items = ImmutableDict._freeze_list(items)

        assert isinstance(frozen_items, tuple)
        assert len(frozen_items) == len(items)
        assert frozen_items[3]["b"][1] == 6
        with pytest.raises(TypeError):
            frozen_items[1]["a"] = 3

    def test_nested_list(self):
        items = [1, [2, [3, [4]]], 5]
        frozen_items = ImmutableDict._freeze_list(items)
        assert isinstance(frozen_items, tuple)
        assert frozen_items[1][1][1][0] == 4
