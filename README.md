# PROJECTNAME

PROJECTNAME is a value-set analysis plugin for [Ghidra][ghidra]. Local variables on a function's stack using Ghidra's intermediate represention results on binaries without debug symbols.
  
## Value-set Analysis

Value-set analysis (VSA) is an abstract interpretation that produces a soudns estimate of the set of addresses or numeric values that each register and variable can take. To achieve this, VSA uses a combination of numeric-analysis and pointer-analysis.

Numeric-analysis produces an over-approximation of the value-set of integer valuesthat each non-pointer variabl eand register can take.

Pointer-analysis produces an over-approximation of the value-set of addresses that a pointer variable or register can take.

## Environment

PROGRAMNAME was developed and tested on Ubuntu 18.04.3LTS and deployed on Ghidra v9.1.

## Usage on Ubuntu 18.04.3LTS

Install [Ghidra][ghidra].

Download the this repository and create a soft-link to 'redev' named 'ghidra_scripts' in the home directory.

Run the script 'VSA_IR.java' from Ghidra's GUI.

NOTE: By default, the script processes the function 'main' and prints the results to the file 'VSA_IR_Output' in the home directory. Change the function to be processed by changing the variable 'func_name' in VSA_IR.java. Change the output location by changing the variable 'output_dir' in VSA_IR.java

[ghidra]: https://github.com/NationalSecurityAgency/ghidra
