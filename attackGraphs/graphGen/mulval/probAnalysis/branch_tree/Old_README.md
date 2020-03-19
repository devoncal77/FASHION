Using Attack Graphs for security optimization

I: MulVal
    A. MulVal is an open source piece of software used for attack graph generation to be used for security analysis. Given a network configuration and a set of vulnerabilities, MulVal should determine whether an attack path exists for an attacker to achieve a goal such as executing code as the root user on a machine. 

    B. Installation:
        1. In order to use MulVal, the following software must be installed:
            a. GraphViz
            b. MySQL
            c. XSB
        2. The current version of MulVal can be found here: 
        3. Uncompress the file using:
            $ tar xzf mulval.tar.gz
        4. The environmental variable MULVALROOT should point to this package's root folder
            Include $MULVALROOT/bin and $MULVALROOT/utils in PATH
        5. To ensure MulVal is installed properly, go to the program's folder.
            a. Go to the folder /testcases/3host
            b. Run the command:
            $ graph_gen.sh -v -p input.P
    A. Writing input files
        1. For generating input files, convert.py can translate network configurations from the functional layer into a MulVal input file.
        2. Input files can be written manually using the following guidelines:
            i. Input files end using the .P extension
            ii. Begin your input file with the clause
                attackGoal(execCode(DEVICE NAME, USER))
            This specifies what the attacker is trying to accomplish. For the purposes of this project, the execCode() clause 
            will be used as the attack goal. Use the "_" symbol to in place of either parameter in execCode() to indicate any device or any user. 
            iii. Use the clause attackerLocated(DEVICE NAME) to specify the starting point for the attacker.
            
