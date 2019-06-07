/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Creates a selection in the current program consisting of the sum
//of all function bodies.
//@category Selection

import ghidra.app.script.GhidraScript;

//Methods of Interfaces Reference, see Reference.java
//Address getFromAddress();
//Address getToAddress();
//int getOperandIndex();
//boolean isxxx();
import ghidra.program.model.symbol.Reference;


//Methods of Interface ReferenceDBManager, see ReferenceDBManager.java
//Reference[] getReferencesTo(Variable var);


import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;


//Methods of Interface Instruction
//InstructionPrototype getPrototype();
//Instruction getNext();
//Instruction getPrevious();
//String getDefaultOperandRepresentation(int opIndex);
//int getOperandType(int opIndex);
//RefType getOperandRefType(int index);
import ghidra.program.model.listing.Instruction;

//Methods of class InstructionDB
//InstructionPrototype getPrototype()
//String getMnemonicString()
//int getNumOperands()
//String getDefaultOperandRepresentation(int opIndex)
import ghidra.program.database.code.InstructionDB;


//Methods of Interface Variable, see Variable.java
//Function getFunction();
//Address getMinAddress();
//int getLength();
//int getStackOffset();
//Symbol getSymbol();
//import ghidra.program.database.function.LocalVariableDB;
//import ghidra.program.database.function.ParameterDB;


//Methods of class VariableSymbolDB, see VariableSymbolDB.java
//FunctionDB getFunction()
//String getName()
import ghidra.program.database.symbol.VariableSymbolDB;


import ghidra.program.model.listing.*;

public class GetRef extends GhidraScript {
    @Override
    public void run() {
        monitor.setMessage("Selecting functions...");

        Listing listing = state.getCurrentProgram().getListing();
        FunctionIterator iter = listing.getFunctions(true);

        while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();
			String fname = f.getName();

            // Entry-point
            println("Function Entry: "+f.getEntryPoint());

            // Name
			println("Function Name: " + fname);
			
			if (!fname.equals("_ZN6Animal9printInfoEv"))
				continue;

            //Parameters
            Parameter[] params = f.getParameters();
            for (int i = 0; i < params.length; i++) {
    			println ("param: " + params[i].getName());
    			Reference[] refs = f.getProgram().getReferenceManager().getReferencesTo(params[i]);
    			for (Reference ref :refs) {
    				println("param ref is: " + ref.toString());
    			}
    		}

    		// Local variables
            Variable[] locals = f.getLocalVariables();
    		for (int i = 0; i < locals.length; i++) {
    			println ("local_var: " + locals[i].getName());
    			Address addr = locals[i].getMinAddress();
    			println (addr.toString());
    			Reference[] refs = f.getProgram().getReferenceManager().getReferencesTo(locals[i]);
    			if (refs.length == 0) {
    				println("No reference");
    			}
    			for (Reference ref :refs) {
    				println("localvar ref is: " + ref.toString());


    				//getDefaultOperandRepresentation()
    			}

    		}

    		// Body
    		AddressSetView set = f.getBody();

	        InstructionIterator iiter = listing.getInstructions(set, true);
	        while (iiter.hasNext() && !monitor.isCancelled()) {
	        	InstructionDB i = (InstructionDB)iiter.next();
	            //println("instruction: "+i.getMnemonicString());
	        	println("instruction: "+i.toString());
	        }
        }

    }
}
