import logging
import time
from dataclasses import dataclass
from typing import Optional
from collections import defaultdict

debug = logging.getLogger("counter").debug


@dataclass
class CounterRecord:
    count: int = 0
    date: Optional[str] = None

    def __post_init__(self):
        if self.date is None:
            self.date = time.asctime()

    def __str__(self):
        return f"{self.count}:{self.date}"

    def __repr__(self):
        return f"CountRecord <{self.count} - {self.date}>"

    def __eq__(self, other):
        if not isinstance(other, CounterRecord):
            return NotImplemented
        return self.count == other.count and self.date == other.date

    def __add__(self, increment: int) -> "CounterRecord":
        """返回一个新的 CounterRecord 对象，不修改原始对象"""
        return CounterRecord(count=self.count + increment, date=time.asctime())

    def increment(self, amount: int = 1) -> "CounterRecord":
        """返回新对象，不产生副作用"""
        return CounterRecord(count=self.count + amount, date=time.asctime())

    def reset_count(self) -> None:
        """重置计数为0"""
        self.count = 0

    def age_count(self, age: int) -> bool:
        """检查是否已过期，如果过期则重置计数"""
        cutoff = int(time.time()) - age
        epoch = time.mktime(time.strptime(self.date, "%a %b %d %H:%M:%S %Y"))
        if cutoff > epoch:
            self.count = 0
            return True
        return False

    # 向后兼容方法
    def get_count(self):
        return self.count

    def get_date(self):
        return self.date


# 使用 defaultdict 创建计数器
def create_counters():
    """创建计数器字典，默认值为 CounterRecord()"""
    return defaultdict(lambda: CounterRecord())
