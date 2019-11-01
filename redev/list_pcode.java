import java.io.IOException;
import java.util.*; // Map & List

import java.lang.Math;
import java.lang.Object;
import java.text.DecimalFormat;

import ghidra.program.model.listing.*;
import ghidra.program.model.block.*; //CodeBlock && CodeBlockImpl
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.scalar.Scalar;

import ghidra.program.model.mem.*;
import ghidra.pcodeCPort.space.*;

import ghidra.program.database.*;
import ghidra.program.database.function.*;
import ghidra.program.database.code.*;

import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.*;

import ghidra.util.task.TaskMonitor; // TaskMonitor
import ghidra.app.script.GhidraScript;

public class list_pcode extends GhidraScript {

	public void run() {
		Program program = state.getCurrentProgram(); // get binary program
		Language language = program.getLanguage();
		Listing listing = program.getListing(); // get list of all instructions in program
		FunctionIterator iter = listing.getFunctions(true);  // iterator for all functions in program
		Set<String> pcodeSeen = new HashSet<String>();
		
		while (iter.hasNext() && !monitor.isCancelled()) { // loop all functions
			Function f = iter.next(); // curr function
			AddressSetView addrSV = f.getBody(); // get address range function
			String info = String.format("Function name: %s || Function entry: %s", f.getName(), f.getEntryPoint());
			println(info);
			InstructionIterator iiter = listing.getInstructions(addrSV,true); // iterator for function instructions
			
			while (iiter.hasNext()) { // loop all instructions
				Instruction inst = iiter.next(); // curr instruction
				int numOperand = inst.getNumOperands(); // number of operands for this instruction
				String toPrint = String.format("-- %s", inst.getMnemonicString());
				print(toPrint);
				for (int i = 0 ; i < inst.getNumOperands() ; i++) { // for all operands of this instruction
					String printable = String.format(" %s", inst.getOpObjects(i).toString());
					print(printable);
				}
				print("\n");
				
				PcodeOp[] opcodes = inst.getPcode(); // array of pcode presenting instruction
				
				for (int i = 0; i < opcodes.length ; i++) { // loop all pcode for this instruction
					String temp = String.format("---- %s (", opcodes[i].getMnemonic());
					print(temp);
					for (int j = 0 ; j < opcodes[i].getNumInputs() ; j++) { // for all inputs of this pcode instruction
						
						/*if (opcodes[i].getInput(j).isConstant()) {
							opcodes[i].getInput(j).trim();
							printf("Integer: %d", Integer.parseInt(opcodes[i].getInput(j).toString(language)));
						}*/
						
						String printable = String.format(" %s ", opcodes[i].getInput(j).toString(language)); // ghdira requires the language of the target program to accurately decode the aruguements
						print(printable);
						/*if (opcodes[i].getInput(j).isConstant()) { // TRIM AND PRINT INPUTS
							opcodes[i].getInput(j).trim();
							println(opcodes[i].getInput(j).toString());
						}*/
					}
					print(")\n");
					
					// PRINT RESULTING VARNODE
					/*if (opcodes[i].getOutput() != null)
						printf("---- output: %s\n", opcodes[i].getOutput().toString());*/
					
					// PRINT OPCODES SEEN
					/*if (!pcodeSeen.contains(opcodes[i].getMnemonic())) 
						pcodeSeen.add(opcodes[i].getMnemonic());*/
				}
			}
			println("-----------------------------------------------------------------------");
		}
		
		// PRINT OPCODES SEEN
		/*Iterator iterator = pcodeSeen.iterator();
		while(iterator.hasNext() ) {
			printf("%s \n", iterator.next());
		}*/
		return;
	}
}
