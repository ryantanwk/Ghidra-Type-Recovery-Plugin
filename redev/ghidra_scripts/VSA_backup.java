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
            long fentry = f.getEntryPoint().getOffset();

            //if (!fname.equals("_ZN6Animal9printInfoEv"))
            //   continue;

            // Entry-point
            if (fentry != 0x0401d92) // _ZN6Animal9printInfoEv
                continue;

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
            //println("instruction xxx: "+i.getMnemonicString());
            println("instruction xxx: "+ i.toString());
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

    public boolean parseFlow(InstructionDB inst) {
        /* Should have two operands, One for reading, and the other for writting */
        int numoprd = inst.getNumOperands();
        System.out.println(numoprd);
        if (numoprd != 2)
            return true;

        OperandType oprdtype = new OperandType();
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        Object[] src = null;
        Object[] dst = null;

        System.out.println("oprand1:" + oprdtype.toString(oprd0ty));
        System.out.println("oprand2:" + oprdtype.toString(oprd1ty));
        if (oprdtype.isAddress(oprd0ty))
            System.out.println("oprd0ty: ADDR");
        else if (oprdtype.isRegister(oprd0ty))
            System.out.println("oprd0ty: REG ");

        if (oprdtype.isAddress(oprd1ty))
            System.out.println("oprd1ty: ADDR");
        else if (oprdtype.isRegister(oprd1ty))
            System.out.println("oprd1ty: REG");

        /* parse the source and destination operands */
        if (oprdtype.doesRead(oprd0ty) && oprdtype.doesWrite(oprd1ty)) {
            src = inst.getOpObjects(0);
            dst = inst.getOpObjects(1);
            System.out.println(162);
        }
        else if (oprdtype.doesRead(oprd1ty) && oprdtype.doesWrite(oprd0ty)) {
            src = inst.getOpObjects(1);
            dst = inst.getOpObjects(0);
            System.out.println(167);
        }

        if (src == null || dst == null)
            return false;

        System.out.println("src:" + src.toString());
        System.out.println("dst:" + dst.toString());
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

class FunctionVSA {
    Program m_program;
    Listing m_listDB;
    FuntionDB m_function;

    Map<String, String> m_registers;  // Track the register status
    Map<String, Set> m_VSATble;       // The function-level VSA-table
    Map<Address, BlockVSA> m_blocks;  // All blocks in this function

    static final String [] x86Regs = {"RAX", "RBX", "RCX", "RDX"};

    public FunctionVSA(Program program, Listing listintDB, FunctionDB func) {
        m_program = program;
        m_listDB = listintDB;
        m_function = func;

        InitCPUStatus();
        InitVSATable();
    }

    boolean InitCPUStatus() {
        /* Set register values to symbols */
        for (String reg: x86Regs) {
            m_registers[reg] = "V" + reg;
        }
    }

    boolean InitVSATable() {
        /* initialize m_VSATable */
        for (String reg: x86Regs) {
            Set vs = new Set();
            vs.add("V" + reg);
            m_VSATble[reg] = vs;
        }

        /* Initialzie vsaTalbe for code blocks */
        AddressSetView addresses = thisFunc.getBody();
        CodeBlockModel blockModel = new BasicBlockModel(state.getCurrentProgram());
        CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(addresses, monitor);

        while (iterator.hasNext()) {
            CodeBlock codeBlock = iterator.next();
            BlockVSA blk = new BlockVSA(codeBlock);
            Address addrStart = codeBlock.getMinaddress();
            m_blocks[addrStart] = blk;
        }
    }
    
    boolean doInterpration() {
        for first block 

        

    }

    boolean traversBlocks(BlockVSA blk, Map<String, String> register_status) {
        Map<String, String> regs;
        
        regs = blk.doVSA(register_status);

        if (blk.hasNext()) {
            if (number of next > 1) {
                register = 
                for (eachnext) {
                    if (bLoopBack && blk.getRunCount() > 10) {
                        continue;   // skip this one
                    }
                    else {
                        traversBlocks(next, regs);
                    }

                }
            }


            else if (bLoopBack && blk.getRunCount() > 10) {
                traversBlocks(next, regs);
            }

            else 
                traversBlocks(next, regs);

        }
        return regs;
    }

    boolean mergeVSATables() {
        for (BlockVSA blk: m_blocks) {
            Map<String, Set> table = blk.getVSATable();
            
        }   
    }

    boolean structAnalysis() {

    }
}


/* just for x86-64 */
class BlockVSA {
    Program m_program;
    Listing m_listDB;
    CodeBlock m_block;
    Map<String, String> m_registers;
    Map<String, Set> m_VSATble;

    final OperandType OPRDTYPE;

    public BlockVSA(Program program, Listing listintDB, CodeBlock blk) {
        m_program = prog;
        m_listDB = listintDB;
        m_block = blk;

        m_VSATble = new Map<String, String>();
        OPRDTYPE = new OperandType();
    }

    void doVSA(Map<String, String> register_status) {
        m_registers = register_status;
        Address addrStart = blk.getMinaddress();
        Address addrEnd = blk.getMaxAddress();
        Addresset addrSet = Addresset(addrStart, addrEnd);
        InstructionIterator iiter = listDB.getInstructions(set, true);

        String tmpAddr = null;
        String tmpValue = null;
        Set tmpSet = null;

        while (iiter.hasNext() && !monitor.isCancelled()) {

            InstructionDB inst = (InstructionDB)iiter.next();
            String op = instr.getMnemonicString();

            if(op.equals("push")) {
                String oprd = inst.getDefaultOperandRepresentation(0);
                int oprdty = inst.getOperandType(0);

                /* Get oprand value & upadte VSA-table */
                if (OPRDTYPE.isRegister(oprdty)) { // register
                    tmpValue = regStatus[oprd];
                }
                else if (OPRDTYPE.isScalar(oprdty)){ // Constant value
                    tmpValue = oprd;
                }
                else { // must be address: two memory oprand does't supported by x86 and ARM
                    System.out.println("Wrong operand");
                }

                tmpAddr = regStatus["RSP"];
                tmpSet = vsaTble[tmpAddr];
                if (tmpSet == null) {
                    tmpSet = new Set();
                    vsaTble[tmpAddr] = tmpSet;
                }
                tmpSet.append(tmpValue);

                /* Update VSA-table for RSP */
                tmpValue = regStatus["RSP"];
                tmpValue = symbolSub(tmpValue, 8);
                tmpSet = vsaTble["RSP"];
                assert(tmpSet != null);
                tmpSet.append(tmpValue);

                /* Update RSP register status */
                tmpValue = regStatus["RSP"];
                tmpValue = symbolSub(tmpValue, 8);
                regStatus["RSP"] = tmpValue;
            }

            else if (op.equals("pop")) {
                String oprd = inst.getDefaultOperandRepresentation(0);
                int oprdty = inst.getOperandType(0);

                /* operand must be a reigster. Other type of memory access does't supported by x86 and ARM  */
                assert(OPRDTYPE.isRegister(oprdty));

                /* Get value from stack && update rigister status */
                tmpValue = regStatus["RSP"];
                tmpSet = vsaTble[tmpValue];
                assert(tmpSet != null);
                regStatus[oprd] = tmpValue;

                /* Update RSP register status */
                tmpValue = regStatus["RSP"];
                tmpValue = symbolAdd(tmpValue, 8);
                regStatus["RSP"] = tmpValue;
            }

            else if (op.equals("add")) {
                continue;
            }
            else if (op.equals("sub")) {
                continue;
            }
            else {
                continue;
            }
        }
    }

    /* fix me */
    String symbolAdd(String symbol, long value) {
        return symbol + "+" + String(value);
    }

    /* fix me */
    String symbolSub(String symbol, long value) {
        return symbol + "-" + String(value);
    }

    /* fix me */
    String symbolMul(String symbol, long value) {
        return symbol + "x" + String(value);
    }

    /* fix me */
    String symbolDivd(String symbol, long value) {
        return symbol + "/" + String(value);
    }
}
