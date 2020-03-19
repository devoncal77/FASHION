from __future__ import annotations
from dataclasses import dataclass
from typing import NamedTuple, FrozenSet, Union, Type, Iterable, Mapping, TypeVar, MutableMapping
from numbers import Real
from copy import copy

# T = TypeVar('T', float, Real, BooleanVariable, Monomial)

def NumberedVariables(identifier: str)-> Iterable[BooleanVariable]:
    i = 0
    while 1:
        yield BooleanVariable(f'{identifier}_{i}')
        i+=1

@dataclass(repr=False, frozen=True)
class BooleanVariable:
    descriptor: str
    
    def __mul__(self, other: Union[Real, BooleanVariable, Polynomial, Monomial])-> Union[Polynomial, BooleanVariable, Monomial]:
        if other is self:
            return self
        if isinstance(other, Real):
            if other == 0:
                return EMPTY_MONOMIAL
            if other == 1:
                return self
            return Polynomial({Monomial.fromVariable(self): other})
        if isinstance(other, BooleanVariable):
            return Monomial(frozenset((self,other)))
        if isinstance(other, Monomial):
            return other if self in other.variables else Monomial(other.variables | {self})
        if isinstance(other, Polynomial):
            return Polynomial({monomial*self : coefficient for monomial,coefficient in other.monomials.items()})
    
    def __rmul__(self, other):
        return self*other
    
    def __add__(self, other: Union[Real, BooleanVariable, Polynomial, Monomial])->Union[Polynomial, BooleanVariable]:
        if isinstance(other, Real):
            if other == 0:
                return self
            return Polynomial({Monomial.fromVariable(self):1, EMPTY_MONOMIAL:other})
        if isinstance(other, BooleanVariable):
            if other is self:
                return Polynomial({Monomial.fromVariable(self):2})
            return Polynomial({Monomial.fromVariable(self) : 1, Monomial.fromVariable(other):1})
        if isinstance(other, Monomial):
            if len(other) == 0:
                return self
            if self in other and len(other) == 1:
                return Polynomial({other:2})
            return Polynomial({Monomial.fromVariable(self):1, other:1})
        if isinstance(other, Polynomial):
            if len(other) == 0:
                return self
            mono = Monomial.fromVariable(self)
            if mono in other:
                out: MutableMapping[Monomial, int] = copy(other.monomials)
                if out[mono] == -1:
                    del out[mono]
                else:
                    out[mono] +=1
                return Polynomial(out)
            out = copy(other.monomials)
            out[Monomial.fromVariable(self)] = 1
            return Polynomial(out)
        return NotImplemented
    
    def __neg__(self)->Polynomial:
        return Polynomial({Monomial.fromVariable(self) : -1})
    
    def __sub__(self, other):
        return self + -other
    
    def __repr__(self)->str:
        return self.descriptor
        
@dataclass(repr=False, frozen=True)
class Monomial:
    variables: FrozenSet[BooleanVariable]
    
    @staticmethod
    def fromVariable(var: BooleanVariable)->Monomial:
        return Monomial(frozenset({var}))
    
    def __contains__(self, other:BooleanVariable)->bool:
        return other in self.variables
    def __len__(self)->int:
        return len(self.variables)
        
    def __add__(self, other: Union[Monomial]) -> Union[Monomial, Polynomial]:
        if isinstance(other, Monomial):
            if len(other) == 0:
                return self
            return Polynomial({self:1, other:1})
        return NotImplemented
    
    def __mul__(self, other: Union[Monomial]) -> Union[Monomial]:
        # if len(self) == 0:
        #     return other
        #     # raise ArithmeticError("Cannot multiply empty monomial")
        if isinstance(other, Monomial):
            # if len(other) == 0:
            #     return self
            #     raise ArithmeticError("Cannot multiply empty monomial")
            return Monomial(self.variables | other.variables)
        return NotImplemented
    
    def __neg__(self) -> Polynomial:
        return Polynomial({self:-1})
    
    
    def __repr__(self)->str:
        return f'(* {" ".join(map(str, self.variables))})'
EMPTY_MONOMIAL = Monomial(frozenset())
    
@dataclass(repr=False)
class Polynomial:
    monomials: Mapping[Monomial, Union[Real, int]]
    
    # def __post_init__(self) -> None:
    #     for coefficient in self.monomials.values():
    #         if coefficient == 0:
    #             import inspect
    #             curframe = inspect.currentframe()
    #             calframe = inspect.getouterframes(curframe, 2)
    #             print('caller name:', calframe[2][3], 'line number:', calframe[2][2])
    #             print(self)
    #             raise Exception
    
    def __contains__(self, other: Monomial)->bool:
        return other in self.monomials
    def __len__(self)->int:
        return len(self.monomials)
    def __neg__(self)->Polynomial:
        return Polynomial({i : -j for i,j in self.monomials.items()})
    
    def __sub__(self, other: Union[Polynomial, Monomial])->Polynomial:
        return self + -other
        
    def __add__(self, other:[Polynomial, Monomial, Real])->Polynomial:
        if isinstance(other, Polynomial):
            out = copy(self.monomials)
            for monomial, coefficient in other.monomials.items():
                if monomial in out:
                    if coefficient + out[monomial] == 0:
                        continue
                    out[monomial]+=coefficient
                else:
                    out[monomial]=coefficient
            return Polynomial(out)
        if isinstance(other, Real):
            out = copy(self.monomials)
            if EMPTY_MONOMIAL in out:
                out[EMPTY_MONOMIAL] += other
            else:
                out[EMPTY_MONOMIAL] = other
            if out[EMPTY_MONOMIAL] == 0:
                del out[EMPTY_MONOMIAL]
            return Polynomial(out)
        return NotImplemented
    
    def __rmul__(self,other):
        return self*other
    
    def __mul__(self, other: Union[Polynomial, Monomial, Real, int]) -> Polynomial:
        if isinstance(other, (Real, int)):
            if other == 0:
                return Polynomial({})
            return Polynomial({i : j*other for i,j in self.monomials.items()})
        if isinstance(other, Monomial):
            return Polynomial({i * other : j for i,j in self.monomials.items() if j != 0})
        if isinstance(other, Polynomial):
            out = Polynomial({})
            if len(self) > len(other):
                self, other = other, self
            # from tqdm import tqdm
            for monomial, coefficient in other.monomials.items():
                out += (monomial*self)*coefficient
            return out
        return NotImplemented
    
    def __repr__(self)->str:
        newline = '\n'
        return f'''(+ {f"{newline}   ".join(f'(* {coefficient} {" ".join(map(str, monomial.variables))})' for monomial, coefficient in self.monomials.items())})'''

if __name__ == '__main__':
    def test(i: Union[Polynomial, Monomial, BooleanVariable],j: Union[Polynomial, Monomial, BooleanVariable])->Polynomial:
        return i + j - i*j
    a = BooleanVariable('a')
    b = BooleanVariable('b')
    c = BooleanVariable('c')
    d = BooleanVariable('d')
    e = BooleanVariable('e')
    f = BooleanVariable('f')
    A = a
    B = b*A
    C = c*A
    E = e*test(B,C)
    D = d*test(B,C)
    F = f*test(D,E)
    print(A)
    print(B)
    print(C)
    print(D)
    print(E)
    print(F)