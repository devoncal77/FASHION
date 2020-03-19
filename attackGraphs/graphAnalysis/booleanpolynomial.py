from __future__ import annotations
from typing import (Union, Mapping, TypeVar, Tuple, Optional, Generator,
                    AbstractSet, ValuesView, FrozenSet, Dict)
from numbers import Real
from collections.abc import Hashable
T = TypeVar('T')
S = TypeVar('S')


class FrozenDict(Mapping[T, S], Hashable):
    def __init__(self, default: Union[Mapping[T, S], None] = None) -> None:
        self._hash: Optional[int] = None
        if default is None:
            self._backing: Mapping[T, S] = {}
        elif isinstance(default, FrozenDict):
            self._backing: Mapping[T, S] = default
        else:
            self._backing: Mapping[T, S] = {k: v for k, v in default.items()}

    def __getitem__(self, other: T) -> S:
        try:
            return self._backing[other]
        except Exception as e:
            raise e

    def __iter__(self) -> Generator[T, None, None]:
        for k in self._backing:
            yield k

    def __len__(self) -> int:
        return len(self._backing)

    def __contains__(self, other: object) -> bool:
        return other in self._backing

    def keys(self) -> AbstractSet[T]:
        return self._backing.keys()

    def items(self) -> AbstractSet[Tuple[T, S]]:
        return self._backing.items()

    def values(self) -> ValuesView[S]:
        return self._backing.values()

    def get(self, key: T, default: Optional[S] = None) -> Optional[S]:
        return self[key] if key in self else default

    def __eq__(self, other: object) -> bool:
        pass

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        if self._hash is None:
            self._hash = hash(frozenset(self.items()))
        return self._hash


class NumericMapping(FrozenDict[T, Real]):
    def get(self, key: T, default: Optional[Real] = 0) -> Optional[Real]:
        return self[key] if key in self else default

    def union(self, other: NumericMapping[T]) -> NumericMapping[T]:
        return NumericMapping({k: self.get(k) + other.get(k) for k in self.keys() | other.keys() if k in other or k in self})
    __or__ = union


BooleanMonomial = FrozenSet[str]
EMPTY_MONOMIAL: BooleanMonomial = frozenset()
Q = Mapping[FrozenSet[str], Real]


class BooleanPolynomial(NumericMapping[BooleanMonomial]):
    def __init__(self, arg: Union[str, Real, Q, None] = None) -> None:
        if arg is None:
            NumericMapping.__init__(self)
        elif isinstance(arg, str):
            NumericMapping.__init__(self, {frozenset({arg}): 1})
        elif isinstance(arg, Real):
            NumericMapping.__init__(self, {EMPTY_MONOMIAL: arg})
        else:
            NumericMapping.__init__(self, arg)

    def __add__(self, other: Union[BooleanPolynomial, Real, str]) -> BooleanPolynomial:
        return BooleanPolynomial(self | BooleanPolynomial(other))

    def __neg__(self) -> BooleanPolynomial:
        return BooleanPolynomial({k: -v for k, v in self.items()})

    def __sub__(self, other: BooleanPolynomial) -> BooleanPolynomial:
        return self + -other

    def __mul__(self, other: Union[BooleanPolynomial, Real, str]) -> BooleanPolynomial:
        if other == 0:
            return BooleanPolynomial()
        other = BooleanPolynomial(other)
        out: Dict[FrozenSet[str], Real] = {}
        for i, j in self.items():
            for k, v in other.items():
                monomial = k | i
                if monomial in out:
                    out[monomial] += v * j
                else:
                    out[monomial] = v * j
                if out[monomial] == 0:
                    del out[monomial]
        return BooleanPolynomial(out)

    def __rmul__(self, other: Union[BooleanPolynomial, Real, str]) -> BooleanPolynomial:
        return self * other

    def __repr__(self) -> str:
        def monomial_repr(k: BooleanMonomial, v: Real) -> str:
            if v == 1:
                return f'(* {" ".join(k)})'
            if k == EMPTY_MONOMIAL:
                return str(v)
            return f'(* {v} {" ".join(k)})'
        newline = '\n   '
        return f'(+ {newline.join(monomial_repr(k,v) for k,v in self.items())})'


def numbered_polynomials(identifier: str) -> Generator[BooleanPolynomial, None, None]:
    i = 0
    while 1:
        yield BooleanPolynomial(f'{identifier}_{i}')
        i += 1
