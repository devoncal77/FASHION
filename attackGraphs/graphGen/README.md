# Using Attack Graphs for Security Optimization

## I: MulVal 
### A. Introduction 
    
MulVal is an open source piece of software used for attack graph generation to be used for security analysis. Given a network configuration and a set of vulnerabilities, MulVal should determine whether an attack path exists for an attacker to achieve a goal such as executing code as the root user on a machine.

The instructions laid out are for installation on a Linux system. 

### B. XSB Installation Instructions:
1. XSB needs to be installed for MulVal to work
2. Download XSB from here to your Linux device: http://xsb.sourceforge.net/
3. Uncompress the file using:
<code> $ tar xvzf XSB.tar.gz </code>
4. Go to the directory
/XSB/build
5. Run <code>./configure</code>
6. Run <code>./makesxsb</code>
7. Leave the XSB directory and go to the .bash_profile file.
8. Include the line
<code> export XSBROOT=~/XSB </code>
in the file.
9. Include
<code> $XSBROOT/bin </code>
and
<code> $XSBROOT/utils </code>
in the PATH variable.

### C. GraphViz Installation:

1. GraphViz is also needed to run MulVal. The program can be downloaded here:
        https://graphviz.gitlab.io/_pages/Download/Download_source.html
2. Uncompress the file and run:

    <code>./configure </code>

    <code>make </code>

    <code>make install </code>

### D. MulVal Installation:
1. The current version of MulVal can be found here: http://people.cs.ksu.edu/~xou/argus/software/mulval/readme.html 

2. Uncompress the file using:

    <code>$ tar xzf mulval.tar.gz</code>

3. Open the .bash_profile file

    a. Include <code>$MULVALROOT/bin</code> and <code>$MULVALROOT/utils</code> in the PATH variable
    
    b. Include the line 
    
    <code>export MULVALROOT=~/mulval</code>
    
    in the file
    
    c. Close the file, log out, and log back in

4. Go to the MulVal directory and run:

    <code> make </code>

5. To ensure MulVal is installed properly,

    a. Go to the folder /testcases/3host
            
    b. Run the command:
            
    <code>$ graph_gen.sh -v -p input.P</code>

    c. If the attack graph is produced and AttackGraph.pdf is in the directory, MulVal is running properly.
    
### E. Writing input files
1. For generating input files, convert.py can translate network configurations from the functional layer into a MulVal input file.
    
    a. To run the file use the command:
        
    <code>python convert.py [INPUT_FILE] [NUM_HOSTS] [NUM_CS] [NUM_SA]</code>
        
    b. INPUT_FILE is a text file detailing the flows of the network configuration

    c. NUM_HOSTS indicates number of hosts

    d. NUM_CS indicates number of core switches

    e. NUM_SA indicates number of aggregate switches

    f. The program should output the file "input.P"

2. Input files can also be written manually using the following guidelines:
    
    a. Input files end using the .P extension
    
    b. Begin your input file with the clause
    
    <code>attackGoal(execCode(DEVICE NAME, USER)).</code>

    This specifies what the attacker is trying to accomplish. For the purposes of this project, the execCode() clause will be used as the attack goal. Use the "_" symbol to in place of any parameter in any clause to serve as a wildcard.

    For example, the clause attackGoal(execCode( _, root)). means the attack goal is for the attacker to be able to execute code as root on any device. 
    
    c. Use the clause 
    
    <code>attackerLocated(DEVICE NAME).</code> 
    
    to specify the starting point for the attacker.

    d. Use the clause 
    
    <code>hacl(SOURCE, DESTINATION, PROTOCOL, PORT).</code> 
    
    to detail connections between devices. SOURCE connects to DESTINATION using PROTOCOL at PORT
    
    e. To add vulnerabilities, use the following clauses:
        
    <code>vulExists(DEVICE, 'VUL_NAME', SOFTWARE).</code>
    
    Vulnerability ['VUL_NAME'] exists on device [DEVICE] on software [SOFTWARE] 

    <code>vulProperty('VUL_NAME', ACCESS_VECTOR, CONSEQUENCE).</code>
    
    When detailing the properties of a vulnerability, ['VUL_NAME'] specifys the vulnerability you are assigning properties to. 
    
    Write [ACCESS_VECTOR] as either 'localExploit' or 'remoteExploit' depending on whether the vulnerability can be exploited locally or remotely. 
    
    CONSEQUENCE details the consequence of the vulnerability, the only consequence used for this project is 'privEscalation'. It is also the only relevant consequence that MulVal understands with the default rule set. 

    <code>networkServiceInfo(DEVICE_NAME, SOFTWARE, PROTOCOL, PORT, USER).</code> 
    
    Software [SOFTWARE] is on device [DEVICE_NAME] listening on port [PORT] for traffic [PROTOCOL]

    f. For probability analysis, include the clause 
    
    <code>cvss('VUL_NAME', COMPLEXITY).</code> 
    
    COMPLEXITY is the access complexity associated with a vulnerability on the CVE database that is either high, medium, or low. For COMPLEXITY, put 'l' for low, 'm' for medium, and 'h' for high (Don't include quotes in the clause) 

### F. Running MulVal
1. Once you have your input file ready, use the command:

<code>$ graph_gen.sh -v -p [INPUT_FILE]</code>

a. -v outputs the attack graph in a PDF file and CSV files.

b. -p performs deep trimming on graph to improve visualization

### G. Custom Rule Sets

MulVal has a default rule set that it uses to make its logical deductions. From the MulVal directory, go to the subdirectory "kb" and the rule set can be found in the file "interaction_rules.P".

For future work, it would be worth looking into writing a custom rule set for MulVal if the default rule set proves ill-suited for the purpose of this research project. 

## II. Probability Analysis
    
A. The paper "Aggregating Vulnerability Metrics in Enterprise Networks using Attack Graphs" by Homer lays out an algorithm for calculating the probabilty that an attacker will reach a node on an attack graph based on CVE metrics: http://people.cs.ksu.edu/~zhangs84/papers/JCS.pdf
    
B. The algorithm is partially implemented in the file probAssess.py. 

**As of 07/30/2019, the python file can only run analysis on acyclic graphs but in the paper, an algorithm is laid out such that analysis can be done on cyclic graphs. Refer to Algorithms 4, 5, and 6 from the paper.** 

The python script takes three arguments, the CSV file output of MulVal detailing the nodes of the graph, the CSV file output of MulVal detailing the edges of the graph, and the input file for MulVal. 

**Note: Python file does not correctly calculate probability of a node with multiple immediate predecessors.** 
    
C. After running MulVal, in addition to the attack graph itself, MulVal also outputs "ARCS.CSV" which detail the edges of the graph and "VERTICES.CSV" which detail the nodes of the graph. These two files along with the input file "input.P" need to be present in the directory to run the probability analysis. 

**Contact Info**
If you have any questions, feel free to contact me at nicholas.c.chan@uconn.edu



            