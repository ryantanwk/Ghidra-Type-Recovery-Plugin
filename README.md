# PROJECTNAME

PROJECTNAME is a value-set analysis plugin for [Ghidra][ghidra]. Locate local variables on a function's stack using Ghidra's intermediate represention results on binaries without debug symbols.
  
## Value-set Analysis

Value-set analysis (VSA) is an abstract interpretation that produces a sound estimate of the set of addresses or numeric values that each register and variable can take. To achieve this, VSA uses a combination of numeric-analysis and pointer-analysis.

Numeric-analysis produces an over-approximation of the value-set of integer values that each non-pointer variable and register can take.

Pointer-analysis produces an over-approximation of the value-set of addresses that a pointer variable or register can take.

## Environment

PROGRAMNAME was developed and tested on Ubuntu 18.04.3LTS and deployed on Ghidra v9.1.

## Installation

Install [Ghidra][ghidra].

Clone this repository to your device.

Create a symbolic link to 'src' named 'ghidra_scripts' in the home directory using `ln`.

> sudo ln -s <path to 'src'> <path to home directory>/ghidra_scripts

## Usage on Ubuntu 18.04.3LTS

Launch Ghidra.

Run the script 'VSA_IR.java' from Ghidra's GUI.

NOTE: By default, the script processes the function 'main' and prints the results to the file "VSAoutput_<function name>.txt" to in the home directory; in the default setting the filename will be "VSAoutput_main.txt". Change the function to be processed by changing the variable 'func_name' in VSA_IR.java. Change the output directory by changing the variable 'output_dir' in VSA_IR.java

[ghidra]: https://github.com/NationalSecurityAgency/ghidra
