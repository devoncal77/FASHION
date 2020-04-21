class EdgesData:
    def __init__(self,i,j,capacity,cost):
        self.i = i
        self.j = j
        self.cap = capacity
        self.cost = cost
    @staticmethod
    def fromJson(dict):
        return EdgesData(dict['i'],dict['j'],dict['capacity'],dict['cost'])
    def __repr__(self):
        return "{(" + str(self.i) + "," + str(self.j) + ") : cap -> "+str(self.cap) + ", cost -> "+str(self.cost)+"}"
    def __str__(self):
        return "{(" + str(self.i) + "," + str(self.j) + ") : cap -> "+str(self.cap) + ", cost -> "+str(self.cost)+"}"
