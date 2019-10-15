import java.io.IOException;
import java.util.*; // Map & List

import java.lang.Math;
import java.lang.Object;
import java.text.DecimalFormat;

import ghidra.program.model.listing.*;
import ghidra.program.model.block.*; //CodeBlock && CodeBlockImpl
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
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

public class test extends GhidraScript {

	public void run() {
		Program program = state.getCurrentProgram(); // get binary program
		Listing listing = program.getListing(); // get list of all instructions in program
		FunctionIterator iter = listing.getFunctions(true);  // iterator for all functions in program

		while (iter.hasNext() && !monitor.isCancelled()) { // loop all functions
			println("-----------------------------------------------------------------------");
			Function f = iter.next(); // curr function
			AddressSetView addrSV = f.getBody(); // get address range function
			String info = String.format("Function name: %s || Function entry: %s", f.getName(), f.getEntryPoint());
			println(info);
			InstructionIterator iiter = listing.getInstructions(addrSV,true); // iterator for function instructions
			while (iiter.hasNext()) { // loop all instructions
				Instruction inst = iiter.next(); // curr instruction
				String toPrint = String.format("-- %s", inst.getMnemonicString());
				println(toPrint);

				PcodeOp[] opcodes = inst.getPcode(); // array of pcode presenting instruction
				for (int i = 0; i < opcodes.length ; i++) { // loop all pcode for this instruction
					String temp = String.format("---- %s", opcodes[i].getMnemonic());
					println(temp);
				}
			}
			println("-----------------------------------------------------------------------");
		}
		return;
	}
}
