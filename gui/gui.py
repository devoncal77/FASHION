from Tkinter import *
from tkColorChooser import askcolor
import Tkconstants, tkFileDialog
from Utils import *

import PIL
from PIL import ImageTk, Image
# impotyt rsvg,cairo
from dataStructures import *
from .NetworkViewer import *
# from model.binaryRisk.sdn import MonolithicModel
# from model.binaryRisk.sdn import NetworkViewer
# from model.binaryRisk.sdn import DROP
# from model.binaryRisk.sdn import Solution
from model.attackGraphRisk.model import AttackGraphModel
from model.attackGraphRisk.minimizedGraph import AttackGraphModel as MinimizedModel
from model.attackGraphRisk.maxRiskPath import AttackGraphModel as MaxPathModel
from model.attackGraphRisk.hybrid import AttackGraphModel as HybridModel
# from model.attackGraphRisk.maxRiskPath import AttackGraphModel

from model.attackGraphRisk.cyclicalRisk import cyclicalRisk, wrapSolution
from dataStructures.network import Network
# from verifier.Checker import Checker
import json
import os
import time


#### add toggle button debug mode
class Application(Frame):
    def chooseInstance(self):
        self.filename = tkFileDialog.askopenfilename(initialdir = ".",title = "Select file",filetypes = (("json files","*.json"),("all files","*.*")))
        if(self.filename != None): 
            self.instance = self.filename
            self.run["state"] = "normal"

    def updateSolution(self,solution):
        self.solution = solution

    def updateImage(self):
        base = os.path.basename(self.instance)
        self.outfile = os.path.splitext(base)[0]
        self.viewer.run(self.outfile)
        self.refreshCanvas()
        # self.viewer.printDotSource()
        
    def solve(self):
        if self.instance == None:
            return
        print "open instance :%s" %(self.instance)
        with open(self.instance, "r") as read_file:
            data = json.load(read_file)
            myStart = time.time()
            self.net = self.readInstance(data)
            self.net.makeModel()
            sol  = self.net.run()
            wAG, wCompCost = wrapSolution(sol,self.net)
            (sol.SCC,sol.riskMeasure) = cyclicalRisk(wAG, wCompCost)
            myEnd = time.time()
            # sol.check = Checker.check(self.net,sol)
            sol.writeStats("stats.csv")
            print "objVal: " , sol.objVal
            print "time:", myEnd-myStart
            print repr(sol)
            # print "blocked : %d/%d " %(len(self.net.flows),len(sol.blockedG()))
            self.viewer = NetworkViewer(self.net,debug=True,nbT=len(self.net.traffics))
            self.viewer.addFlows(filter(lambda k : sol.pv[k] > 0.1  or (k[1] == k[0].dest and k[2] == sol.net.asink[0]),sol.pv.keys()),bv=sol.blocked())
            self.viewer.addFirewalls(map(lambda (f,r): r,filter(lambda k : sol.wv[k] != 0.0,sol.wv.keys())), drop=DROP.ALL)
            self.viewer.addFirewalls(filter(lambda k : sol.wtv[k] != 0.0,sol.wtv.keys()), drop=DROP.TRAFFIC)
            self.updateSolution(sol)
            self.updateImage()

    def readInstance(self,data):
        inputFile = os.path.basename(self.instance)
        res = None
        if self.AGClass != None :
            res  = self.modelClass(Network.fromJson(data,inputFile=inputFile), self.AGClass.fromJson(data),self.fw,self.sw,widthW=self.widthW,depthW=self.depthW)
        else:
            res = self.modelClass(Network.fromJson(data,inputFile=inputFile))
        return res
       
    def wheel(self, event):
        ''' Zoom with mouse wheel '''
        # print str(event.delta)
        scale = 1.0
        # Respond to Linux (event.num) or Windows (event.delta) wheel event
        if event.num == 5 or event.delta < 0:
            scale        *= self.delta
            self.imscale *= self.delta
        if event.num == 4 or event.delta > 0:
            scale        /= self.delta
            self.imscale /= self.delta
        # Rescale all canvas objects
        x = self.top.canvasx(event.x)
        y = self.top.canvasy(event.y)
        self.top.scale('all', x, y, scale, scale)
        self.show_image()
        self.top.configure(scrollregion=self.top.bbox('all'))

    def move_from(self, event):
        ''' Remember previous coordinates for scrolling with the mouse '''
        self.top.scan_mark(event.x, event.y)

    def move_to(self, event):
        ''' Drag (move) canvas to the new position '''
        self.top.scan_dragto(event.x, event.y, gain=1)

    
    def show_image(self):
        # print "show_img"
        ''' Show image on the Canvas '''
        width, height = self.orig_img.size
        if int(self.imscale * width) <= 0 and int(self.imscale * height) <= 0:
            return
        if self.imageid :
            self.top.delete(self.imageid)
            self.imageid = None
            self.top.imagetk = None  # delete previous image from the canvas
        new_size = int(self.imscale * width), int(self.imscale * height)
        self.orig_img.resize(new_size, PIL.Image.ANTIALIAS)
        self.orig_img.convert('RGB').save(self.viewer.imagefile, 'JPEG', quality=95)
        imagetk = ImageTk.PhotoImage(self.orig_img.resize(new_size, PIL.Image.ANTIALIAS))
        # Use self.text object to set proper coordinates
        self.imageid = self.top.create_image(self.top.coords(self.text),
                                                anchor='nw', image=imagetk)
        # print ""+str(self.text)
        self.top.lower(self.imageid)  # set it into background
        self.top.imagetk = imagetk  # keep an extra reference to prevent garbage-collection

    def getColor(self,what):
        color = askcolor()
        # print color
        color = color[1]
        if color == None :
            return
        if(what == "firewall"):
            self.viewer.setFirewallColor(color)
        elif(what == "firewallT"):
            self.viewer.setFirewallTColor(color)
        elif(what == "good"):
            self.viewer.setGoodFColor(color)
        elif(what == "bad"):
            self.viewer.setBadFColor(color)
        self.updateImage()

    def toggle(self):
        if self.toggle_btn.config('relief')[-1] == 'sunken':
            self.toggle_btn.config(relief="raised")
            self.toggle_btn.config(text="OFF")
            self.viewer.setDebug(False)
            self.updateImage()
        else:
            self.toggle_btn.config(relief="sunken")
            self.toggle_btn.config(text="ON")
            self.viewer.setDebug(True)
            self.updateImage()


    def initColorsRow(self):
        self.colors = Label(self, text="Colors")
        self.colors.grid(row=0,column=0)
        self.fwAllColor = Button(self,text="firewalls",command=(lambda: self.getColor("firewall")))
        self.fwAllColor.grid(row=0, column=1)
        self.fwAllColor = Button(self,text="firewalls T",command=(lambda: self.getColor("firewallT")))
        self.fwAllColor.grid(row=0, column=2)
        self.goodColor = Button(self,text="good",command=(lambda: self.getColor("good")))
        self.goodColor.grid(row=0, column=3)
        self.badColor = Button(self,text="bad",command=(lambda: self.getColor("bad")))
        self.badColor.grid(row=0, column=4)
        self.debug = Label(self,text="Debug")
        self.debug.grid(row=0,column=5)
        self.toggle_btn = Button(self,text="ON", width=12, relief="sunken",command=self.toggle)
        self.toggle_btn.grid(row=0,column=6)
    
    def updateSelection(self,evt):
        self.goodFSnapshot = self.dealWithFlowsSelection(self.goodFSnapshot,self.flowsG)
        self.badFSnapshot = self.dealWithFlowsSelection(self.badFSnapshot,self.flowsB)

    def dealWithFlowsSelection(self,flows,box):
        snap = set(box.curselection())
        if len(snap) and (len(flows) != len(snap)):
            diff = snap - flows
            if len(diff) > 0:
                diff = diff.pop()
                if box.get(diff) == 'None':
                    snap = set([0])
                    box.selection_clear(0, END)
                    box.select_set(0)
                else:
                    snap.discard(0)
                    box.selection_clear(0, 0)
                    if box.get(diff) == 'All':
                        box.selection_clear(1, 1)
                        box.selection_clear(3,END)
                        snap = set([2])
                    elif box.get(diff) == 'Blocked':
                        box.selection_clear(2, END)
                        snap = set([1])
                    else :
                        box.selection_clear(1, 2)
                        snap.discard(1)
                        snap.discard(2)
        return snap

    def initWidget(self):
        self.initColorsRow()
        self.flowGN = Label(self,text="Good")
        self.flowGN.grid(row=1,column=3,columnspan=3)
        self.flowBN = Label(self,text="Bad")
        self.flowBN.grid(row=3,column=3,columnspan=3)
        self.flowsG = Listbox(self, selectmode='multiple',exportselection=0)
        self.flowsG.bind('<<ListboxSelect>>', self.updateSelection)
        self.flowsG.configure(state='normal')
        self.flowsG.grid(row=2,column=3,columnspan=3)
        self.flowsB = Listbox(self, selectmode='multiple',exportselection=0)
        self.flowsB.bind('<<ListboxSelect>>', self.updateSelection)
        self.flowsB.configure(state='normal')
        self.flowsB.grid(row=4,column=3,columnspan=3)
        self.goodFSnapshot = set([2])
        self.badFSnapshot = set([2])
        self.firewalls = Label(self,text="firewalls")
        self.allFV = BooleanVar(value=1)
        self.allF = Checkbutton(self, text="all", variable=self.allFV,command=self.updateFW)
        self.allNB = Label(self,text=str(self.viewer.FWAllNB()))
        self.trafficFV = BooleanVar(value=1)
        self.trafficF = Checkbutton(self, text="traffic", variable=self.trafficFV,command=self.updateFW)
        self.trafficNB = Label(self,text=str(self.viewer.FWTNB()))
        self.flowsFV = BooleanVar(value=1)
        self.flowsF = Checkbutton(self, text="flows", variable=self.flowsFV,command=self.updateFW)
        self.flowsNB = Label(self,text=str(self.viewer.FWFNB()))
        self.firewalls.grid(row=6,column=3)
        self.allF.grid(sticky="W",row=5,column=4)
        self.allNB.grid(sticky="W",row=5,column=5)
        self.trafficF.grid(sticky="W",row=6,column=4)
        self.trafficNB.grid(sticky="W",row=6,column=5)
        self.flowsF.grid(sticky="W",row=7,column=4)
        self.flowsNB.grid(sticky="W",row=7,column=5)
        ratio = Label(self,text="Blocked : ")
        self.ratioG = Label(self,text=self.getRatioG())
        self.ratioB = Label(self,text=self.getRatioB())
        ratio.grid(row=8,column=3)
        self.ratioG.grid(row=8,column=4)
        self.ratioB.grid(row=8,column=5)
        self.update = Button(self,text="update",command=self.selectFlow)
        self.update.grid(row=10,column=5)
        self.reset = Button(self,text="reset",command=self.resetFlow)
        self.reset.grid(row=10,column=6)
        self.edgesDatasL = Label(self, text="Edges Data")
        self.edgesDatasL.grid(row=1,column=6)
        self.edgesDatas = Listbox(self,exportselection=0,height=30)
        self.edgesDatas.grid(row=2,rowspan=6,column=6)

    def getRatioG(self):
        nbG = len(self.solution.blockedG())
        nb = len(self.net.G)
        if nbG == nb:
            return "Good : All"
        if nbG == 0:
            return "Good : None"
        return "Good : "+str(nbG)+"/"+str(nb)

    def getRatioB(self):
        nbB = len(self.solution.blockedB())
        nb = len(self.net.B)
        if nbB == nb:
            return "Bad : All"
        if nbB == 0:
            return "Bad : None"
        return "Bad : "+str(nbB)+"/"+str(nb)

    def refreshCanvas(self):
        self.orig_img = PIL.Image.open(self.viewer.imagefile)
        self.show_image()
        # self.photo = ImageTk.PhotoImage(self.orig_img)
        width = self.orig_img.width
        if (width > self.windowWidth):
            width = self.windowWidth/2
        height = self.orig_img.height
        if (height > self.windowHeight):
            height = self.windowHeight/2
        # if self.image == None:
        #     self.image = self.top.create_image(0,0,anchor = NW,image = self.photo) 
        # else:
        #     self.top.itemconfig(self.image, image = self.photo)
        self.top.config(width=width, height=height)
        self.top.grid(row=1,rowspan=8,column=0,columnspan=2)
        self.top.config(scrollregion=self.top.bbox(ALL))
        if self.flowsG != None:
            self.flowsG.delete(0,END)
            self.flowsB.delete(0,END)
            self.edgesDatas.delete(0,END)
        else:
            self.initWidget()
        self.flowsG.insert(END,"None")
        self.flowsB.insert(END,"None")
        self.flowsG.insert(END,"Blocked")
        self.flowsB.insert(END,"Blocked")
        self.flowsG.insert(END,"All")
        self.flowsB.insert(END,"All")
        for i in self.net.traffics:
            self.flowsG.insert(END,"traffic "+str(i))
            self.flowsB.insert(END,"traffic "+str(i))
        lG = sorted(self.net.G, key=lambda x: x.origin)
        for item in lG:
            self.flowsObj[str(item)] = item
            self.flowsG.insert(END,item)
        lB = sorted(self.net.B, key=lambda x: x.origin)
        for item in lB:
            self.flowsObj[str(item)] = item
            self.flowsB.insert(END,item)
        self.flowsG.select_set(2)
        self.flowsB.select_set(2)
        for ed in self.net.cc :
            # print "("+str(ed.i)+","+str(ed.j)+") cap:"+str(ed.cap)+" cost:"+str(ed.cost)
            self.edgesDatas.insert(END,"("+str(ed.i)+","+str(ed.j)+") cap:"+str(ed.cap)+" cost:"+str(ed.cost))

    def selectFlow(self):
        self.viewer.clear()
        goodF = [self.flowsG.get(idx) for idx in self.flowsG.curselection()]
        badF = [self.flowsB.get(idx) for idx in self.flowsB.curselection()]
        goodFID = [idx for idx in self.flowsG.curselection()]
        badFID = [idx for idx in self.flowsB.curselection()]
        flowsV = []
        flows = []
        if not 'None' in goodF:
            if 'All' in goodF:
                flowsV += [str(f) for f in self.net.G]
            elif 'Blocked' in goodF:
                flowsV += [str(f[0]) for f in self.solution.blockedG()]
            else:
                for t in self.net.traffics:
                    if "traffic "+str(t) in goodF:
                        goodF += [str(f) for f in self.net.G if f.t == t]
                        # goodF += filter(lambda i : self.net.G[i].t == t,self.net.G)
                        # goodF.remove("traffic "+str(t))
                flowsV = [f for f in goodF if not f.startswith("traffic")]
        if not 'None' in badF:
            if 'All' in badF:
                flowsV += [str(f) for f in self.net.B]
            elif 'Blocked' in badF:
                flowsV += [str(f[0]) for f in self.solution.blockedB()]
            else:
                for t in self.net.traffics:
                    if "traffic "+str(t) in badF:
                        badF += [str(f) for f in self.net.B if f.t == t]
                        # badF += filter(lambda i : self.net.B[i].t == t,self.net.B)
                        # badF.remove("traffic "+str(t))
                flowsV += [f for f in badF if not f.startswith("traffic")]
        print flowsV
        for f in flowsV:
            flows.append(self.flowsObj[f])
        if len(flows) > 0:
            pv = self.solution.pv
            self.viewer.addFlows(filter(lambda k : pv[k] != 0.0 and k[0] in flows,pv.keys()))
        self.updateFW()
        self.updateImage()
        if len(goodF) > 0 :
            self.flowsG.selection_clear(0, END)
            for idx in goodFID:
                self.flowsG.select_set(idx)
        if len(badF) > 0 :
            self.flowsB.selection_clear(0, END)
            for idx in badFID:
                self.flowsB.select_set(idx)

    def resetFlow(self):
        self.viewer.clear()
        wv = self.solution.wv
        wtv = self.solution.wtv
        self.viewer.addFirewalls(self.solution.FW(), drop=DROP.ALL)
        self.viewer.addFirewalls(self.solution.FWT(), drop=DROP.TRAFFIC)
        self.viewer.addFlows(self.solution.flows(),bv=self.solution.blocked())
        self.updateImage()

    def updateFW(self):
        if(not self.allFV.get()):
            self.viewer.clearFWA()
        else:
            self.viewer.addFirewalls(self.solution.FW(), drop=DROP.ALL)
        if(not self.trafficFV.get()):
            self.viewer.clearFWT()
        else:
            self.viewer.addFirewalls(self.solution.FWT(), drop=DROP.TRAFFIC)
        if(not self.flowsFV.get()):
            self.viewer.clearFWF()
        else:
            print "update firewallsF"
        self.updateImage()

    def askInstance(self):
        self.top = Canvas(self)
        self.xscrollbar = AutoScrollbar(self, orient=HORIZONTAL)
        self.xscrollbar.grid(row=9, column=0, columnspan=2, sticky=E+W)
        self.yscrollbar = AutoScrollbar(self)
        self.yscrollbar.grid(row=1, column=2,rowspan=8, sticky=N+S)
        self.xscrollbar.config(command=self.top.xview)
        self.yscrollbar.config(command=self.top.yview)
        self.top.config(yscrollcommand=self.yscrollbar.set)
        self.top.config(xscrollcommand=self.xscrollbar.set)
        self.top.config(scrollregion=self.top.bbox(ALL))
        self.top.bind('<ButtonPress-1>', self.move_from)
        self.top.bind('<B1-Motion>',     self.move_to)
        self.top.bind('<MouseWheel>', self.wheel)  # with Windows and MacOS, but not Linux
        self.top.bind('<Button-5>',   self.wheel)  # only with Linux, wheel scroll down
        self.top.bind('<Button-4>',   self.wheel)  # only with Linux, wheel scroll up
        self.text = self.top.create_text(0, 0, anchor='nw', text='Scroll to zoom')
        self.imscale = 1.0
        self.imageid = None
        self.delta = 1.25
        self.flowsG = None
        self.flowsB = None
        self.QUIT = Button(self,text="QUIT",command=self.quit)
        self.QUIT.grid(row=10,column=0)
        self.chooser = Button(self,text="Instance",command=self.chooseInstance)
        self.chooser.grid(row= 10,column=1)
        self.run = Button(self,text="run",command=self.solve,state='normal')
        self.run.grid(row=10,column=3)

    def __init__(self, master=None,maxWidth=1500,maxHeight=1300,model=AttackGraphModel,attackGraph=None,fname=None,fw=1,sw=1,widthW = 1, depthW=1):
        Frame.__init__(self, master)
        self.solution = None
        self.windowWidth = maxWidth
        self.windowHeight = maxHeight
        self.image = None
        self.instance = fname
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.flowsObj = {}
        self.pack()
        self.askInstance()
        self.modelClass = model
        self.AGClass = attackGraph
        self.fw=fw
        self.sw=sw
        self.widthW=widthW
        self.depthW=depthW
        if fname:
            self.solve()


def run(modelClass=AttackGraphModel,AGClass=None,fname=None,fw=1,sw=1,widthW = 1, depthW = 1):
    root = Tk()
    root.title("OptimalSDN")
    root.lift()
    root.attributes('-topmost',True)
    root.after_idle(root.attributes,'-topmost',False)

    # Gets the requested values of the height and widht.
    windowWidth = root.winfo_reqwidth()
    windowHeight = root.winfo_reqheight()
    # print("Width",windowWidth,"Height",windowHeight)

    # Gets both half the screen width/height and window width/height
    positionRight = int(root.winfo_screenwidth()/3 - windowWidth/2)
    positionDown = int(root.winfo_screenheight()/3 - windowHeight/2)
    
    # Positions the window in the center of the page.
    root.geometry("+{}+{}".format(positionRight, positionDown))
    app = Application(master=root,maxWidth=root.winfo_screenwidth(),maxHeight=root.winfo_screenheight(),model=modelClass,attackGraph=AGClass,fname=fname,fw=fw,sw=sw,widthW = widthW, depthW=depthW)
    app.mainloop()
    try:
        root.destroy()
    except:
        pass