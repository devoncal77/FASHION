#!/usr/bin/python

from gui.gui import *
from model.attackGraphRisk.model import *
from dataStructures.attackGraph import AttackGraph
from dataStructures.booleanGraph import BooleanGraph
import sys

if len(sys.argv) == 2:
    f = sys.argv[1]
else:
    f="./smallToy.json"

run(MinimizedModel,BooleanGraph,f)
