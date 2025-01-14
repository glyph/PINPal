from unittest import TestCase
from ..txtui import show


class TxtUiTests(TestCase):
    """
    Some simple tests for rendering values.
    """

    def test_show(self) -> None:
        """
        L{show} renders a password prompt which includes placeholders both for
        hidden and forgotten elements of the underlying generated password.
        """

        self.assertEqual(
            show("/", ["two", "three", "four"], 4, 1), "••••/°°°°/three/four"
        )
        self.assertEqual(
            show("/", ["two", "three", "four"], 4, 2), "••••/°°°°/°°°°/four"
        )
