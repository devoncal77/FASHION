# Testing Code
## Python
* Any code that uses type annotations will most likely run better on python 3.7 or 4 due to improvements to the core python type annotation system
* Use [Numba](https://numba.pydata.org/), CYthon, or PyPy for best performance
### Libraries:
- [SymPy](https://www.sympy.org/en/download.html)
- [Gurobi](https://www.gurobi.com/)
- [Graphviz](https://www.graphviz.org/)
## Kotlin
- Use maven to auto-import dependencies
- Build with `mvn clean install`
---
## `bayesian.py`
* Contains implementations of Bayesian Networks, as well as functions to facilitate in their generation
  * Can be used to view the expression tree of the calculation process
* Requires python 3.5
## `booleanpolynomial.py`
* `BooleanPolynomial`
  * Code pertaining to the generation of Boolean Multivariate Polynomials with real valued coefficients
  * printing is represented through S-Expressions
* `numbered_polynomials`
  * Used to generate numbered variables for use in polynomial construction
* `FrozenDict`
  * Implementation of a FrozenDict, similair to the standard `frozenset`
* *Requires python 3.7*
## `model.py`
* Implements a 0-1 Integer Programming model for modeling risk in attack graphs
* Requires python 3.5
* Requires Gurobipy, graphviz
## `MultiThreadedMinCut`
* Kotlin implementation of Bayesian Network

