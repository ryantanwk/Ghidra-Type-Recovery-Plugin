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

import ghidra.program.model.listing.*;
import ghidra.program.model.address.AddressSetView;

import ghidra.program.database.function.*;
import ghidra.program.database.code.InstructionDB;

import ghidra.program.model.lang.OperandType;

public class VSA extends GhidraScript {
    Program program;
    Listing listing;
   
    @Override
    public void run() {
        program = state.getCurrentProgram();
        listing = program.getListing();

        FunctionIterator iter = listing.getFunctions(true);        
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            
            String fname = f.getName();
            if (!fname.equals("printInfo"))
                continue;
            
            // Entry-point
            println("Function Entry: " + f.getEntryPoint());
            
            // Name
            println("Function Name: " + f.getName());
            
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
            
            trackThisFlow(f);
        }
        
    }

    private boolean trackThisFlow(Function vtFunc) {        
        //Get "this" Parameters
        Parameter[] params = vtFunc.getParameters();
        Parameter pThis = null;

        println("Function Name: " + vtFunc.getName());

        for (Parameter p: params) {
            String pName = p.getName();
            println ("find param: " + pName);
            if (pName.equals("this")) {
                pThis = p;
                break;
            }
        }
        if (pThis == null)
            return false;
        
        ThisflowAnalysis analysis = new ThisflowAnalysis();
    	AddressSetView set = vtFunc.getBody();
    		
        InstructionIterator iiter = listing.getInstructions(set, true);
        while (iiter.hasNext() && !monitor.isCancelled()) {
            InstructionDB i = (InstructionDB)iiter.next();
            //println("instruction: "+i.getMnemonicString());
            analysis.parseFlow(i);
        }
        return true; 
    }    
}

/* Node of data flow */
class DFNode {
    String thisExp;
    //Type Mem or REG;
    DFNode [] nexts;
}

class ThisflowAnalysis{
    // Source and destination oprand type
    static final int SRCREGMEM = 1;
    static final int SRCOTHERS = 0;
    static final int SRCREG = 1;
    static final int SRCMEM = 3;
    
    static final int DSTREGMEM = 1 << 4;
    static final int DSTOTHERS = 0;     
    static final int DSTREG = 1 << 4;
    static final int DSTMEM = 3 << 4;
    
    // Data propagation type
    static final int REG2REG = SRCREG | DSTREG;
    static final int REG2MEM = SRCREG | DSTMEM;

    static final int MEM2REG = SRCMEM | DSTREG;
    static final int MEM2MEM = SRCMEM | DSTMEM;


    // Internal data members
    //Regs [] activeRegs;
    //Mems [] activeMems;

    DFNode root = null;
    
    public ThisflowAnalysis() {

    }

    public boolean parseFlow(Instruction inst) {
        /* Should have two operands, One for reading, and the other for writting */
        if (inst.getNumOperands() != 2)
            return true;

        OperandType oprdtype = new OperandType();
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        Object[] src = null;
        Object[] dst = null;

        /* parse the source and destination operands */
        if (oprdtype.doesRead(oprd0ty) && oprdtype.doesWrite(oprd1ty)) {
            src = inst.getOpObjects(0);
            dst = inst.getOpObjects(1);
        }
        else if (oprdtype.doesRead(oprd1ty) && oprdtype.doesWrite(oprd0ty)) {
            src = inst.getOpObjects(1);
            dst = inst.getOpObjects(0);            
        }

        if (src == null || dst == null)
            return false;

        //Do propagation
        int optype = 0;

        switch(optype) {
            case REG2REG:
            case REG2MEM:
            case MEM2REG:
            case MEM2MEM:
            default:
            break; 
        }

        return true;


    }

    boolean referMem() {
        return true;
    }

    boolean updateMem() {
        return true;
    }

    boolean referReg() {
        return true;
    }

    boolean updateReg() {
        return true;
    }
}
