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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.database.code.InstructionDB;
import ghidra.program.model.listing.*;

public class funcinfo extends GhidraScript {
    @Override
    public void run() {
        monitor.setMessage("Selecting functions...");
     
        Listing listing = state.getCurrentProgram().getListing();
        FunctionIterator iter = listing.getFunctions(true);
        
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            
            // Entry-point
            println("Function Entry: "+f.getEntryPoint());
            
            // Name
            println("Function Name: "+f.getName());
            
            //Parameters
            Parameter[] params = f.getParameters();
            for (int i = 0; i < params.length; i++) {
    			println ("param: " + params[i].getName());
    		}
            
    		// Local variables
            Variable[] locals = f.getLocalVariables();
    		for (int i = 0; i < locals.length; i++) {
    			println ("local_var: " + locals[i].getName());
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
