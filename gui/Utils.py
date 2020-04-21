from Tkinter import *


class AutoScrollbar(Scrollbar):
    # a scrollbar that hides itself if it's not needed.  only
    # works if you use the grid geometry manager.
    def set(self, lo, hi):
        if float(lo) <= 0.0 and float(hi) >= 1.0:
            # grid_remove is currently missing from Tkinter!
            self.tk.call("grid", "remove", self)
        else:
            self.grid()
        Scrollbar.set(self, lo, hi)
    def pack(self, **kw):
        raise TclError, "cannot use pack with this widget"
    def place(self, **kw):
        raise TclError, "cannot use place with this widget"



def pairwise(lst):
    """ yield item i and item i+1 in lst. e.g.
        (lst[0], lst[1]), (lst[1], lst[2]), ..., (lst[-1], None)
    """
    if not lst: return
    #yield None, lst[0]
    for i in range(len(lst)-1):
        yield lst[i], lst[i+1]
    # yield lst[-1], None


def enum(**named_values):
    return type('Enum', (), named_values)

    
def edgesFromFlows(pv,good,bad,edges2traffic):
    ge = []
    be = []
    for p in pv:
        if(p[0] in good):
            ge.append((p[1],p[2]))
        elif(p[0] in bad):
            be.append((p[1],p[2]))
        if  (p[1],p[2]) not in edges2traffic:
            edges2traffic[(p[1],p[2])] = set([])
        edges2traffic[(p[1],p[2])].add(p[0].t) 
    return (ge,be)