"""Integer helpers shared by the formula modules."""


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)
