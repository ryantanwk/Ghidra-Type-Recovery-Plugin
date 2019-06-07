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

import java.io.IOException;
import java.util.*;     // Map & List

import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;    //CodeBlock && CodeBlockImpl
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;

import ghidra.program.database.*;
import ghidra.program.database.function.*;
import ghidra.program.database.code.*;


import ghidra.util.task.TaskMonitor;    // TaskMonitor
import ghidra.app.script.GhidraScript;


public class SymbolicVSA extends GhidraScript {
    private Program program;
    private Listing listing;

    @Override
    public void run() {
        program = state.getCurrentProgram();
        listing = program.getListing();

        FunctionIterator iter = listing.getFunctions(true);
        FunctionSMAR smar;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            String fname = f.getName();
            long fentry = f.getEntryPoint().getOffset();

            // Entry-point
            if (fentry != 0x0401d92) // _ZN6Animal9printInfoEv
                continue;

            println("Function Entry: " + f.getEntryPoint());
            println("Function Name: " + f.getName());

            smar = new FunctionSMAR(program, listing, f, monitor);
            smar.doRecording();
        }
    }
}


/*
   Function-level symbolic memory access recording (SMAR)
   Every symbolic value defines a domain
   */
class FunctionSMAR {
    private final Program m_program;
    private final Listing m_listDB;
    private final Function m_function;
    private TaskMonitor m_monitor;

    private HashMap<String, String> m_registers;        // Track register status
    private HashMap<String, String> m_memories;         // Track memory status
    private Map<String, Set<String>> m_SMARTable;   // The function-level memory-access table
    private Map<Address, BlockSMAR> m_blocks;       // All blocks in this function

    /* for x86-64 */
    static final String [] x86Regs = {"RAX", "RBX", "RCX", "RDX"};

    public FunctionSMAR(Program program, Listing listintDB, Function func, TaskMonitor monitor) {
        m_program = program;
        m_listDB = listintDB;
        m_function = func;
        m_monitor = monitor;

        InitMachineStatus();
        InitSMARTable();
        constructCFG();
    }

    private void InitMachineStatus() {
        /* Set register values to symbols */
        for (String reg: x86Regs) {
            m_registers.put(reg, "V" + reg);
        }
        /* Doesn't need to initialize memory space */
    }

    private void InitSMARTable() {
        if (m_SMARTable == null) {
            m_SMARTable = new HashMap<String, Set<String>>();
        }

        /* initialize m_SMART */
        for (String reg: x86Regs) {
            Set<String> vs = new HashSet<String>();
            vs.add("V" + reg);
            m_SMARTable.put(reg, vs);
        }
    }

    private void constructCFG() {
        /* Create BlockSMAR for each codeblock */
        AddressSetView addrSV = m_function.getBody();
        CodeBlockModel blkModel = new BasicBlockModel(m_program);

        try {
            CodeBlockIterator codeblkIt = blkModel.getCodeBlocksContaining(addrSV, m_monitor);
            while (codeblkIt.hasNext()) {
                CodeBlock codeBlk = codeblkIt.next();
                BlockSMAR smarBlk = new BlockSMAR(m_program, m_listDB, m_function, codeBlk);
                Address addrStart = codeBlk.getFirstStartAddress();
                m_blocks.put(addrStart, smarBlk);
            }
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.out.println("Failed to get basic blocks");
        }

        /* Initialize control-flow graph */        
        Set<BlockSMAR> nxtSMARblks = new HashSet<BlockSMAR>();
        try {
            for (BlockSMAR curSMARBlk: m_blocks.values()) {
                /* find the next-blocks of current code-block */
                CodeBlock curCodeBlk = curSMARBlk.getCodeBlock();
                CodeBlockReferenceIterator di = curCodeBlk.getDestinations(m_monitor);
                while (di.hasNext())  {
                    CodeBlockReference ref = di.next();
                    CodeBlock nxtCodeBlk = ref.getDestinationBlock();
                    Address addrStart = nxtCodeBlk.getFirstStartAddress();
                    BlockSMAR nxtSMARBlk = m_blocks.get(addrStart);
                    if (nxtSMARBlk != null) {
                        nxtSMARblks.add(nxtSMARBlk);
                    }
                }

                /* set the m_next filed of current SMARTblock */
                curSMARBlk.setNexts(nxtSMARblks);

                /* start next cycle */
                nxtSMARblks.clear();
            }            
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.out.println("Failed to contruct the CFG");
        }
        
    }

    public boolean doRecording() {
        CodeBlockModel blkModel = new BasicBlockModel(m_program);
        Address addr = m_function.getEntryPoint();

        try {
            CodeBlock firstBlk = blkModel.getCodeBlockAt(addr, m_monitor);
            BlockSMAR smarBlk = m_blocks.get(firstBlk.getFirstStartAddress());

            /* traverse all code-blocks recusivly */
            smarBlk.traversBlock(m_SMARTable, m_registers, m_memories);
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.out.println("Failed to traversBlock");
        }

        return true;
    }

    boolean mergeVSATables() {
        //for (BlockSMAR blk: m_blocks) {
        //Map<String, Set<String>> table = blk.getVSATable();

        /* merge two tables */
        //}
        return true;
    }

    boolean structAnalysis() {
        return true;
    }
}


/* just for x86-64 */
class BlockSMAR {
    private Program m_program;
    private Listing m_listDB;
    private Function m_function;
    private CodeBlock m_block;

    private Set<BlockSMAR> m_nexts;
    private int m_runs;

    private final OperandType OPRDTYPE;

    public BlockSMAR(Program program, Listing listintDB, Function function, CodeBlock block) {
        m_program = program;
        m_listDB = listintDB;
        m_function = function;
        m_block = block;

        OPRDTYPE = new OperandType();
        m_runs = 0;
    }

    public CodeBlock getCodeBlock() {
        return m_block;
    }

    public void setNexts(Set<BlockSMAR> nexts) {
        m_nexts = nexts;
    }

    public Set<BlockSMAR> getNexts() {
        return m_nexts;
    }

    /* traverse all code-blocks recusivly */
    public boolean traversBlock(Map<String, Set<String>> memory_access_table, HashMap<String, String> register_status, HashMap<String, String> memory_status) {

        doRecording(memory_access_table, register_status, memory_status);

        /* travers the next blocks */
        if (m_nexts.size() >= 1) {
            for (BlockSMAR nextBlk: m_nexts) {
                boolean bLoopBack = (nextBlk.m_block.getFirstStartAddress().getOffset() < m_block.getFirstStartAddress().getOffset());
                if (bLoopBack && nextBlk.getRunCount() > 10) {
                    continue;   // skip this one
                }
                else {
                    /* fork register status if needs */
                    HashMap<String, String> regs;
                    HashMap<String, String> mems;
                    if (m_nexts.size() >= 2) {
                        regs = (HashMap<String, String>)register_status.clone();
                        mems = (HashMap<String, String>)memory_status.clone();
                    }
                    else {
                        regs = register_status;
                        mems = memory_status;
                    }

                    nextBlk.traversBlock(memory_access_table, regs, mems);
                }
            }
        }
        return true;
    }

    void doRecording(Map<String, Set<String>> memory_access_table, HashMap<String, String> register_status, HashMap<String, String> memory_status) {
        m_runs += 1;    // increase execution counter

        Map<String, Set<String>> smarTable = memory_access_table;
        Map<String, String> regStatus = register_status;
        Map<String, String> memStatus = memory_status;

        /* iterate every instruction in this block */
        String tmpAddr = null;
        String tmpValue = null;
        Set<String> tmpSet = null;
        AddressSet addrSet = m_block.intersect(m_function.getBody());
        InstructionIterator iiter = m_listDB.getInstructions(addrSet, true);

        while (iiter.hasNext()) {

            InstructionDB inst = (InstructionDB)iiter.next();
            String op = inst.getMnemonicString();

            if(op.equals("push")) {
                String oprd = inst.getDefaultOperandRepresentation(0);
                int oprdty = inst.getOperandType(0);

                /* Get oprand value & upadte VSA-table */
                if (OPRDTYPE.isRegister(oprdty)) { // register
                    tmpValue = regStatus.get(oprd);
                }
                else if (OPRDTYPE.isScalar(oprdty)){ // Constant value
                    tmpValue = oprd;
                }
                else { // must be address: two memory oprand does't supported by x86 and ARM
                    System.out.println("Wrong operand");
                }

                tmpAddr = regStatus.get("RSP");
                tmpSet = smarTable.get(tmpAddr);
                if (tmpSet == null) {
                    tmpSet = new HashSet<String>();
                    smarTable.put(tmpAddr, tmpSet);
                }
                tmpSet.add(tmpValue);

                /* Update VSA-table for RSP */
                tmpValue = regStatus.get("RSP");
                tmpValue = symbolicSub(tmpValue, 8);
                tmpSet = smarTable.get("RSP");
                assert(tmpSet != null);
                tmpSet.add(tmpValue);

                /* Update RSP register status */
                tmpValue = regStatus.get("RSP");
                tmpValue = symbolicSub(tmpValue, 8);
                regStatus.put("RSP", tmpValue);
            }

            else if (op.equals("pop")) {
                String oprd = inst.getDefaultOperandRepresentation(0);
                int oprdty = inst.getOperandType(0);

                /* operand must be a reigster. Other type of memory access does't supported by x86 and ARM  */
                assert(OPRDTYPE.isRegister(oprdty));

                /* Get value from stack && update rigister status */
                tmpValue = regStatus.get("RSP");
                tmpSet = smarTable.get(tmpValue);
                assert(tmpSet != null);
                regStatus.put(oprd, tmpValue);

                /* Update RSP register status */
                tmpValue = regStatus.get("RSP");
                tmpValue = symbolicAdd(tmpValue, 8);
                regStatus.put("RSP", tmpValue);
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
    String symbolicAdd(String symbol, long value) {
        return String.format("%s + %d", symbol, value);
    }

    /* fix me */
    String symbolicSub(String symbol, long value) {
        return String.format("%s - %d", symbol, value);
    }

    /* fix me */
    /*String symbolicMul(String symbol, long value) {
        return symbol + "x" + String(value);
    }*/

    /* fix me */
    /*String symbolicDiv(String symbol, long value) {
        return symbol + "/" + String(value);
    }*/

    int getRunCount() {
        return m_runs;
    }
}
