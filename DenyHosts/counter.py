import logging
import time
from dataclasses import dataclass
from collections import defaultdict
from typing import DefaultDict, Optional, Union

debug = logging.getLogger("counter").debug


@dataclass
class CounterRecord:
    count: int = 0
    date: Optional[str] = None

    def __post_init__(self) -> None:
        if self.date is None:
            self.date = time.asctime()

    def __str__(self) -> str:
        return f"{self.count}:{self.date}"

    def __repr__(self) -> str:
        return f"CounterRecord <{self.count} - {self.date}>"

    def __eq__(self, other: object) -> Union[bool, type]:
        if not isinstance(other, CounterRecord):
            return NotImplemented
        return self.count == other.count and self.date == other.date

    def __add__(self, increment: int) -> "CounterRecord":
        return CounterRecord(count=self.count + increment, date=time.asctime())

    def increment(self, amount: int = 1) -> "CounterRecord":
        return CounterRecord(count=self.count + amount, date=time.asctime())

    def reset_count(self) -> None:
        self.count = 0

    def age_count(self, age: int) -> bool:
        cutoff = int(time.time()) - age
        epoch = time.mktime(time.strptime(self.date, "%a %b %d %H:%M:%S %Y"))
        if cutoff > epoch:
            self.count = 0
            return True
        return False

    def get_count(self) -> int:
        return self.count

    def get_date(self) -> Optional[str]:
        return self.date


def create_counters() -> DefaultDict[str, CounterRecord]:
    return defaultdict(lambda: CounterRecord())
