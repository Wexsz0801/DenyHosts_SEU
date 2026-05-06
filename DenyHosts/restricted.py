import os
from typing import Any, Set

from .constants import RESTRICTED_USERNAMES


class Restricted:
    def __init__(self, prefs: Any) -> None:
        self.filename = os.path.join(prefs["ETC_DIR"], RESTRICTED_USERNAMES)
        self.__data: Set[str] = set()
        self.load_restricted()

    def load_restricted(self) -> None:
        try:
            fp = open(self.filename, "r")
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                if line[0] == "#":
                    continue
                self.__data.add(line)
        except IOError:
            pass

    def get_restricted(self) -> Set[str]:
        return self.__data
