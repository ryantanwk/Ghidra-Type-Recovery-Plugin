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
import ghidra.program.database.references.ReferenceDB;
import ghidra.program.model.listing.*;

public class CreateStruct extends GhidraScript {
    @Override
    public void run() {
           
        Listing listing = state.getCurrentProgram().getListing();
        FunctionIterator fiter = listing.getFunctions(true);
        CodeUnitFormat cuf = getCodeUnitFormat();
        
        DefineStruct defc;
        
        while (fiter.hasNext() && !monitor.isCancelled()) {
            Function f = fiter.next();
            String fname = f.getName();
            
            if (fname.equals("main"))
                println("Find main");
                
            if (!fname.equals("_ZN6Animal9printInfoEv"))
                continue;
                        
            // Function name & entry
            println("Function Name: " + fname);
            
    		// Body
    		AddressSetView set = f.getBody();    		
	        InstructionIterator iiter = listing.getInstructions(set, true);
	        
	        while (iiter.hasNext() && !monitor.isCancelled()) {
	        	InstructionDB instr = (InstructionDB)iiter.next();
	        	String si = cuf.getRepresentationString(instr);
	        	
	            //println("instruction: "+i.getMnemonicString());
	        	println("instruction: " + si);
	        }
        }
        
    }   
}

class DefineStruct {
    References [] data;
    Reference [] vptr;    
}
