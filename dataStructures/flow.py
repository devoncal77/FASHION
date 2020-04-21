class Flow:
    currentId = 0
    def __init__(self,o,d,f,s,v):
        self.origin = int(o)
        self.dest = int(d)
        self.flow = f
        self.t    = s
        self.value = v
        self.id = Flow.getId()
        self.links = []
    def setSrc(self,src):
        self.src = src
    def setSink(self,sink):
        self.sink = sink
    @staticmethod
    def getId():
        Flow.currentId += 1
        return Flow.currentId
    @staticmethod
    def fromJson(dict):
        return Flow(dict['o'],dict['d'],dict['f'],dict['s'],dict['v'])
    def __repr__(self):
        return "f(%d,%d,%f,%s,%d)" % (self.origin,self.dest,self.flow,str(self.t),self.id)
