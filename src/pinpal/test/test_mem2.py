from dataclasses import dataclass, field
from uuid import uuid4

from pinpal.difficulty import SCryptParameters
from pinpal.mem2 import TokenType
from twisted.internet.defer import Deferred
from twisted.trial.unittest import SynchronousTestCase as TestCase

from ..mem2 import Memorization2

kdf = SCryptParameters.forNPower(2)


@dataclass
class TestPrompter:
    pw: str | None
    asks: list[tuple[str, str]] = field(default_factory=list)
    tells: list[str] = field(default_factory=list)

    async def askForPassword(self, question: str, reminder: str) -> str | None:
        self.asks.append((question, reminder))
        return self.pw

    async def tellUser(self, message: str) -> None:
        self.tells.append(message)


class Mem2Tests(TestCase):
    def test_generateOne(self) -> None:
        salt = bytes.fromhex("3843877f197ef3338b9f5f96be076e01")
        key = kdf.kdf(salt=salt, password=b"too many")
        now = 1.0
        mem2 = Memorization2(
            id=str(uuid4()),
            label="my label",
            targetTokenCount=3,
            knownTokens=["too", "many"],
            generatedCount=2,
            salt=salt,
            key=key,
            tokenType=TokenType.words,
            kdf=kdf,
            guesses=[],
            maxKnown=2,
            dirty=False,
            _time=lambda: now,
            _choice=lambda whatever: "secrets",
        )
        prompter = TestPrompter("too many")

        async def promptme() -> None:
            await mem2.prompt(prompter)

        self.successResultOf(Deferred.fromCoroutine(promptme()))
        self.successResultOf(Deferred.fromCoroutine(promptme()))
        self.successResultOf(Deferred.fromCoroutine(promptme()))
        self.successResultOf(Deferred.fromCoroutine(promptme()))
        prompter.pw = "too many secrets"
        self.successResultOf(Deferred.fromCoroutine(promptme()))
        self.assertEqual(
            prompter.tells,
            [
                "3 correct entries to go before leveling up",
                "2 correct entries to go before leveling up",
                "1 correct entries to go before leveling up",
                "leveling up",
                "5 correct entries to go before leveling up",
            ],
        )
        self.assertEqual(
            prompter.asks,
            [
                ("my label", "too many"),
                ("my label", "too many"),
                ("my label", "°°°° many"),
                ("my label", "°°°° many"),
                ("my label", "•••• many secrets"),
            ],
        )
        # self.assertEqual(prompter.asks, [('my label', 'too many secrets')])
        # self.assertEqual(prompter.tells, ['5 correct entries to go before leveling up'])
