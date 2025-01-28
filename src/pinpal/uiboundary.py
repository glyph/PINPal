from typing import Protocol

class UserPrompter(Protocol):
    async def askForPassword(self, question: str, reminder: str) -> str | None:
        ...

    async def tellUser(self, message: str) -> None:
        ...
