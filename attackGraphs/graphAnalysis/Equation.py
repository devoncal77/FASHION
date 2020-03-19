from __future__ import annotations
from collections import namedtuple
from typing import NamedTuple, FrozenSet, Union, Type, Iterable, Mapping
from numbers import Complex, Real
from dataclasses import dataclass, replace, field


def NumberedSymbols(identifier: str, isBoolean: bool=False)-> Iterable[Symbol]:
    i = 0
    while 1:
        yield Symbol(f'{identifier}_{i}', isBoolean=isBoolean)
        i+=1

@dataclass(repr=False, frozen=True)
class Symbol:
    descriptor: str
    isBoolean: bool = False
    exponent: float = 1
    
    def __pow__(self, other: float) -> Symbol:
        if self.isBoolean:
            return self
        return replace(self, exponent=other*self.exponent)
    
    def __neg__(self)->Monomial:
        return Monomial(frozenset((self,)), coefficient=-1)
    
    def __add__(self, other: Union[Symbol, Monomial])-> Union[Polynomial, Monomial]:
        if isinstance(other, Symbol):
            if other == self:
                return Monomial(frozenset((self,)), coefficient=2)
            return Polynomial(frozenset((Monomial(frozenset((self,))), Monomial(frozenset((other,))))))
        if isinstance(other, Monomial):
            return Polynomial(frozenset((Monomial(frozenset((self,))), other)))
        return NotImplemented

    def __lt__(self: Symbol, other: Symbol) -> bool:
        return isinstance(other, Symbol) and (len(self.descriptor) < len(other.descriptor) or self.descriptor < other.descriptor)
    
    def __mul__(self, other: Union[Symbol, Monomial, float, Polynomial])->Union[Monomial,Symbol, Polynomial]:
        if isinstance(other, Symbol):
            if other.descriptor == self.descriptor:
                return replace(self, exponent=1 if self.isBoolean or other.isBoolean else self.exponent+other.exponent)
            return Monomial(frozenset((self,other)))
        if isinstance(other, Monomial):
            return other.__mul__(self)
            # if self.descriptor in other.descriptors:
            #     pass
        if isinstance(other, Real):
            return Monomial(frozenset((self,)), coefficient=other)
        if isinstance(other, Polynomial):
            return Polynomial(frozenset(self * monomial for monomial in other.monomials))
        return NotImplemented
        
    def __rmul__(self, other: float)->Monomial:
        return self * other

    def __repr__(self)->str:
        # if self.exponent == 1:
        #     return f'{self.descriptor}'
        # if self.exponent == 0:
        #     return '0'
        # return f'{self.descriptor}**{self.exponent}'
        if self.exponent == 1:
            return f'{self.descriptor}'
        if self.exponent == 0:
            return '0'
        return f'(expt {self.descriptor} {self.exponent})'

@dataclass(repr=False, frozen=True)
class Monomial:
    symbols: FrozenSet[Symbol]
    coefficient: float = 1
    descriptors: FrozenSet[str] = field(init=False, hash=False)
    _descriptorToSymbol: Mapping[str, Symbol] = field(init=False, hash=False)
    
    
    def __post_init__(self)->None:
        object.__setattr__(self,'descriptors', frozenset(i.descriptor for i in self.symbols))
        object.__setattr__(self, '_descriptorToSymbol', {i.descriptor : i for i in self.symbols})
    
    def __neg__(self)->Union[Monomial, float]:
        if self.coefficient == 0:
            return Monomial(frozenset(),coefficient=0)
        return replace(self, coefficient=self.coefficient * -1)
    
    def __repr__(self) -> str:
        # if self.coefficient == 1:
        #     return ''.join(map(str, sorted(self.symbols)))
        # if self.coefficient == 0:
        #     return '0'
        # return f'''{self.coefficient}{''.join(map(str, sorted(self.symbols)))}'''
        if self.coefficient == 1:
            return f'''(* {' '.join(map(str, sorted(self.symbols)))})'''
        if self.coefficient == 0:
            return '0'
        return f'''(* {self.coefficient} {' '.join(map(str, sorted(self.symbols)))})'''
    
    def __sub__(self, other: Union[Symbol,Monomial, Polynomial])->Union[Monomial, Polynomial, Symbol, float]:
        if self.coefficient == 0:
            return -other
        return self + -other
    
    def __add__(self, other: Union[Symbol,Monomial, Polynomial, float]) -> Union[Monomial, Polynomial, Symbol, float]:
        if self.coefficient == 0:
            return other
        if isinstance(other, Symbol):
            if len(self.symbols) == 1 and other in self.symbols:
                return replace(self, coefficient=self.coefficient+1)
            return Polynomial(frozenset((self,Monomial(frozenset((other,))))))
        if isinstance(other, Monomial):
            if self.symbols == other.symbols:
                return replace(self, coefficient=self.coefficient+other.coefficient)
            return Polynomial(frozenset((self,other)))
        if isinstance(other, Polynomial):
            return other + self
        if isinstance(other, Real):
            return Polynomial(frozenset((self,Monomial(frozenset(), coefficient=other))))
        return NotImplemented
    
    def __mul__(self, other: Union[float, Symbol, Monomial, Polynomial])->Union[Monomial, Polynomial, float]:
        if self.coefficient == 0:
            return Monomial(frozenset(),coefficient=0)
        if isinstance(other, Symbol):
            if other.descriptor in self.descriptors:
                found: Symbol = self._descriptorToSymbol[other.descriptor]
                return replace(self, symbols=self.symbols-{found} | {replace(found, exponent= 1 if found.isBoolean else found.exponent + other.exponent)})
            return replace(self, symbols=self.symbols | {other})
        if isinstance(other, Real):
            return replace(self, coefficient=self.coefficient*other)
        if isinstance(other, Monomial):
            out: Union[Monomial, Polynomial] = self
            for symbol in other.symbols:
                out*=symbol
            out*=other.coefficient
            return out
        if isinstance(other, Polynomial):
            out = other
            for symbol in self.symbols:
                out*=symbol
            out*= self.coefficient
            return out
        raise NotImplementedError(f'{type(other)}')
    
    def __lt__(self, other: Monomial):
        pass
                
@dataclass(repr=False, frozen=True)
class Polynomial:
    monomials: FrozenSet[Monomial]
    _symbolsToMonomial: Mapping[FrozenSet[Symbol], Monomial] = field(init = False, hash= False)
    
    def _initSymbolsToMonomial(self) -> None:
        object.__setattr__(self, '_symbolsToMonomial', {i.symbols : i for i in self.monomials})
    
    def __neg__(self)->Polynomial:
        return Polynomial(frozenset(-i for i in self.monomials))
    
    def __add__(self, other: Union[Symbol, Monomial, Polynomial]) -> Polynomial:
        if isinstance(other, Symbol):
            other = Monomial(frozenset((other,)))
        elif isinstance(other, Real):
            other = Monomial(frozenset(), coefficient=other)
        if isinstance(other, Monomial):
            try:
                result = other.symbols in self._symbolsToMonomial
            except AttributeError:
                self._initSymbolsToMonomial()
                result = result = other.symbols in self._symbolsToMonomial
            if result:
                found = self._symbolsToMonomial[other.symbols]
                return Polynomial((self.monomials - {found}) | {replace(found, coefficient=found.coefficient + other.coefficient)})
            return Polynomial(self.monomials | {other})
        if isinstance(other, Polynomial):
            
            if not hasattr(self, '_symbolsToMonomial'):
                self._initSymbolsToMonomial()
            if not hasattr(other, '_symbolsToMonomial'):
                other._initSymbolsToMonomial()
            overlap = self._symbolsToMonomial.keys() & other._symbolsToMonomial.keys()
            nonOverlap = other._symbolsToMonomial.keys() - overlap
            out = Polynomial((self.monomials - {self._symbolsToMonomial[symbols] for symbols in overlap}) | {replace(self._symbolsToMonomial[symbols], coefficient=self._symbolsToMonomial[symbols].coefficient + other._symbolsToMonomial[symbols].coefficient) for symbols in overlap} | {other._symbolsToMonomial[symbols] for symbols in nonOverlap})
            # for symbols in nonOverlap:
            #     out += other._symbolsToMonomial[symbols]
            
            return out
        return NotImplemented

    def __sub__(self, other: Union[Symbol, Monomial,Polynomial])->Polynomial:
        return self + -other
    
    def __mul__(self, other: Union[Symbol, float, Polynomial])->Polynomial:
        if isinstance(other, (Symbol, Real)):
            return Polynomial(frozenset(monomial*other for monomial in self.monomials))
        if isinstance(other, Polynomial):
            out = 0
            for monomial in other.monomials:
                out = monomial * self + out
            return out
        return NotImplemented
    
    def __repr__(self)->str:
        newline = '\n'
        return f'''
(+ 
  {(newline+'  ').join(map(str, self.monomials))})'''
        # return ' + '.join(map(str, self.monomials))
    
    def __contains__(self, other: Monomial)->bool:
        return other in self.monomials

if __name__ == '__main__':
    def test(i: Union[Polynomial, Monomial, Symbol],j: Union[Polynomial, Monomial, Symbol])->Polynomial:
        return i + j - i*j
    a = Symbol('a')
    b = Symbol('b')
    c = Symbol('c')
    d = Symbol('d')
    e = Symbol('e')
    f = Symbol('f')
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
    # print(a + b - a*b)
    # print(c*(a+b-a*b))