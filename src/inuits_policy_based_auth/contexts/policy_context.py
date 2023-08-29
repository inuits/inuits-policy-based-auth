from inuits_policy_based_auth.helpers.access_restrictions import AccessRestrictions


class PolicyContext:
    """
    A class containing data about the context of an applied authorization policy.

    Authorization policies use this class to influence access determination.

    Properties
    ----------
    access_restrictions : AccessRestrictions
        A class containing properties used to restrict access.
    access_verdict : bool | None
        The verdict that will influence access determination.
    """

    def __init__(self):
        self._access_restrictions = AccessRestrictions()
        self._access_verdict = None

    @property
    def access_restrictions(self):
        """A class containing properties used to restrict access."""

        return self._access_restrictions

    @property
    def access_verdict(self):
        """The verdict that will influence access determination.

        By default None.

        If True: access will be allowed.
        If False: access will be denied.
        If None: access will be denied if no other policy allows.
        """

        return self._access_verdict

    @access_verdict.setter
    def access_verdict(self, access_verdict: bool | None):
        self._access_verdict = access_verdict
