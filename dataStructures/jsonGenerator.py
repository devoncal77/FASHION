# -*- coding: utf-8 -*-
"""
Created on Wed Oct 30 15:59:40 2019

@author: ena02002
"""

class JSON_Maker:
    def __init__(self, list_of_nums=[]):
        self.list_of_nums = list_of_nums
        self.flows = []
    def find_start_end(self, current_list = []):
        i5 = []
        j5 = []
        for toup in current_list:
            #start and end values of the path: start must be in i list and end must be in j list
            
            i5.append(toup[0])
            j5.append(toup[1])
                
                
                
             
                
        x,y = tuple(set(i5).symmetric_difference(set(j5)))
            
        if x in i5:
            return (x,y)
        else:
            return (y,x)
                
                    
    def list_struct(self, current_list = []):
        result = []
        start,end = self.find_start_end(current_list)
        i = start
        while i != end:
            for j in current_list:
                if i == j[0]:
                    result.append(j[0])
                    i = j[1]
        result.append(end)
        return result
    def dictionary_maker(self):
        for list_1 in self.list_of_nums:
            thing = self.list_struct(list_1)
            flow = dict(Route = thing)
            self.flows.append(flow)
        flowns = dict(Flows = self.flows)
        print flowns

if __name__ == '__main__':
    l = [[(5,3),(7,5),(3,1),(1,6),(6,8)],[(3,5),(2,1),(4,2),(1,3)]]
    cool = JSON_Maker(l)
    cool.dictionary_maker()
    print ("Hello World")    
    