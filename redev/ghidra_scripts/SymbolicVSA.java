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
import java.lang.Math;

import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;    //CodeBlock && CodeBlockImpl
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.scalar.Scalar;


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
        HardwareArch arch = new LArchX86();
        program = state.getCurrentProgram();
        listing = program.getListing();

        FunctionIterator iter = listing.getFunctions(true);
        FunctionSMAR smar;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            String fname = f.getName();
            long fentry = f.getEntryPoint().getOffset();

            // Entry-point
            if (fentry != 0x401e1e)
                continue;

            println("Function Entry: " + f.getEntryPoint());
            println("Function Name: " + f.getName());

            smar = new FunctionSMAR(arch, program, listing, f, monitor);
            smar.doRecording();

            Map<String, Set<String>> smart = smar.getMAARTable();
            println(smart.toString());
        }
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


/*
   Function-level symbolic memory access recording (SMAR)
   Every symbolic value defines a domain
   */
class FunctionSMAR {
    private final HardwareArch m_arch;
    private final Program m_program;
    private final Listing m_listDB;
    private final Function m_function;
    private TaskMonitor m_monitor;

    private HashMap<String, String> m_registers;        // Track register status
    private HashMap<String, String> m_memories;         // Track memory status
    private Map<String, Set<String>> m_SMARTable;   // The function-level memory-access table
    private Map<Address, BlockSMAR> m_blocks;       // All blocks in this function

    public FunctionSMAR(HardwareArch arch, Program program, Listing listintDB, Function func, TaskMonitor monitor) {
        m_arch = arch;
        m_program = program;
        m_listDB = listintDB;
        m_function = func;
        m_monitor = monitor;

        m_registers = new HashMap<String, String>();
        m_memories = new HashMap<String, String>();
        m_SMARTable = new HashMap<String, Set<String>>();
        m_blocks = new HashMap<Address, BlockSMAR>();

        InitMachineStatus();
        InitSMARTable();
        constructCFG();
    }

    private void InitMachineStatus() {
        /* Set register values to symbols */
        String[] allRegs = m_arch.getRegisters();
        for (String reg: allRegs) {
            m_registers.put(reg, "V" + reg);
        }
        /* Doesn't need to initialize memory space */
    }

    private void InitSMARTable() {
        if (m_SMARTable == null) {
            m_SMARTable = new HashMap<String, Set<String>>();
        }

        /* initialize m_SMART */
        String[] allRegs = m_arch.getRegisters();
        for (String reg: allRegs) {
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
                BlockSMAR smarBlk = new BlockSMAR(m_arch, m_program, m_listDB, m_function, codeBlk);
                Address addrStart = codeBlk.getFirstStartAddress();
                m_blocks.put(addrStart, smarBlk);
            }
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("Failed to get basic blocks");
        }

        /* Initialize control-flow graph */
        try {
            for (BlockSMAR curSMARBlk: m_blocks.values()) {
                /* find the next-blocks of current code-block */
                Set<BlockSMAR> nxtSMARblks = new HashSet<BlockSMAR>();
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
            }
        }
        catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("Failed to contruct the CFG");
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
            System.err.println("Failed to traversBlock");
        }

        return true;
    }

    Map<String, Set<String>> getMAARTable() {
        return  m_SMARTable;
    }
}


/* just for x86-64 */
class BlockSMAR {
    private HardwareArch m_arch;
    private Program m_program;
    private Listing m_listDB;
    private Function m_function;
    private CodeBlock m_block;


    private Set<BlockSMAR> m_nexts;
    private int m_runs;

    private final OperandType OPRDTYPE;

    /* used as pointers */
    Map<String, Set<String>> m_smarTable;
    Map<String, String> m_regStatus;
    Map<String, String> m_memStatus;


    public BlockSMAR(HardwareArch arch, Program program, Listing listintDB, Function function, CodeBlock block) {
        m_arch = arch;
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
        /* Recording memory access conducted by current code block */
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

        m_smarTable = memory_access_table;
        m_regStatus = register_status;
        m_memStatus = memory_status;

        /* iterate every instruction in this block */
        AddressSet addrSet = m_block.intersect(m_function.getBody());
        InstructionIterator iiter = m_listDB.getInstructions(addrSet, true);

        while (iiter.hasNext()) {
            InstructionDB inst = (InstructionDB)iiter.next();
            int nOprand = inst.getNumOperands();

            if (nOprand == 0) {
                _doRecording0(inst);
            }
            else if (nOprand == 1)  {
                _doRecording1(inst);
            }
            else if (nOprand == 2)  {
                _doRecording2(inst);
            }
            else {

            }
        }
    }

    void _doRecording0(InstructionDB inst) {

    }

    void _doRecording1(InstructionDB inst) {
        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

        String op = inst.getMnemonicString();

        if(op.equalsIgnoreCase("push")) {
            /* push reg; push 0x1234; */
            System.out.println(inst.toString());
            String oprd = inst.getDefaultOperandRepresentation(0);
            int oprdty = inst.getOperandType(0);

            /* Get oprand value & upadte MAR-table */
            if (OPRDTYPE.isRegister(oprdty)) { // register
                strValue = m_regStatus.get(oprd);
            }
            else if (OPRDTYPE.isScalar(oprdty)){ // Constant value
                strValue = oprd;
            }
            else { // must be address: two memory oprand does't supported by x86 and ARM
                System.err.println("Wrong operand");
            }

            /* Update MAR-table & register status */
            strAddr = m_regStatus.get("RSP");
            strAddr = symbolicSub(strAddr, 8);
            updateRegister("RSP", strAddr);

            /* Update MAR-table & memory status */
            strAddr = m_regStatus.get("RSP");
            updateMemoryWriteAccess(strAddr, strValue);
        }

        else if (op.equalsIgnoreCase("pop")) {
            /* pop reg */
            System.out.println(inst.toString());
            String oprd = inst.getDefaultOperandRepresentation(0);
            int oprdty = inst.getOperandType(0);

            /* operand must be a reigster. Other type of memory access does't supported by x86 and ARM  */
            assert(OPRDTYPE.isRegister(oprdty));

            // strAddr = m_regStatus.get("RSP");
            // updateMemoryReadAccess(strAddr);

            /* Get value from stack && update rigister status */
            strValue = m_regStatus.get("RSP");
            strValue = m_memStatus.get(strValue);
            updateRegister(oprd, strValue);

            /* Clean memory status */
            strValue = m_regStatus.get("RSP");
            m_memStatus.remove(strValue);

            /* Update RSP register status */
            strValue = m_regStatus.get("RSP");
            strValue = symbolicAdd(strValue, 8);
            updateRegister("RSP", strValue);
        }
        else {
            System.out.println("fix-me:387");
        }
    }

    void _doRecording2(InstructionDB inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);
        String op = inst.getMnemonicString();

        String strVal0, strVal1, strAddr0, strAdd1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;
        
        Object[] objs;

        if (op.equalsIgnoreCase("sub")) {
            /* sub reg, reg; sub reg, 0x1234; sub reg, mem; sub mem, reg; sub mem, 0x1234 */
            System.out.println(inst.toString());

            if (OPRDTYPE.isRegister(oprd0ty)) {                
                oprd0 = inst.getDefaultOperandRepresentation(0);

                if (OPRDTYPE.isRegister(oprd1ty)) {
                    /* sub reg, reg */                
                    strVal0 = m_regStatus.get(oprd0);
                    oprd1 = inst.getDefaultOperandRepresentation(1);
                    strVal1 = m_regStatus.get(oprd1);

                    /* fix-me */
                    //strValue = symbolicSub(String Symobl0, String Symbol1);
                    strValue = "";

                    updateRegister(oprd0, strValue);
                }
                else if (OPRDTYPE.isScalar(oprd1ty)){
                    /* sub rsp, 8; */
                    strVal0 = m_regStatus.get(oprd0);
                    oprd1 = inst.getDefaultOperandRepresentation(1);
                    strValue = symbolicSub(strVal0, Integer.decode(oprd1));       

                    /* upate register status */
                    updateRegister(oprd0, strValue);
                }
                else {
                    /* others */
                    System.out.println("fix-me:433");
                }
            }
            else {
                /* others */
                System.out.println("fix-me:439");
            }
        }

        else if (op.equals("add")) {
            return;
        }

        else if (op.equalsIgnoreCase("mov")) {
            /* mov reg, reg; mov reg, mem; mov reg, 0x1234; mov mem, reg; mov mem, 0x1234 */
            if (OPRDTYPE.isRegister(oprd0ty)) {
                System.out.println(inst.toString());
                
                oprd0 = inst.getDefaultOperandRepresentation(0);
                if (OPRDTYPE.isRegister(oprd1ty)) {
                    /* mov reg, reg */
                    oprd1 = inst.getDefaultOperandRepresentation(1);

                    strValue = m_regStatus.get(oprd1);
                    updateRegister(oprd0, strValue);
                }
                else if (OPRDTYPE.isScalar(oprd1ty)){
                    /* mov rax, 8; */
                    oprd1 = inst.getDefaultOperandRepresentation(1);

                    /* upate register status */
                    updateRegister(oprd0, oprd1);
                }
                else { /* memory oprand */
                    objs = inst.getOpObjects(1);

                    if (objs.length == 1) {
                        /* mov reg, [reg]; mov reg, [0x48000] */
                        if (objs[0] instanceof Register) {
                            Register r = (Register)objs[0];

                            /* update memory access */
                            strValue = m_regStatus.get(r.getName());
                            updateMemoryReadAccess(strValue);

                            /* fetch the value from the memory elememt */
                            strValue = m_memStatus.get(strValue);

                            /* upate register status */
                            updateRegister(oprd0, strValue);

                        }
                        else if (objs[0] instanceof Scalar) {
                            Scalar s = (Scalar)objs[0];

                            /* update memory access */
                            strAddress = String.valueOf(s.getValue());
                            updateMemoryReadAccess(strAddress);

                            /* fetch the value from the memory elememt */
                            strValue = m_memStatus.get(strAddress);

                            /* upate register status */
                            updateRegister(oprd0, strValue);
                        }
                        else {
                            /* Throw exception */
                            System.err.println("fix-me 500");
                        }

                    }
                    else if (objs.length == 2) {
                        /* Registet + Scaler: i.e [RBP + -0x28] */
                        assert((objs[0] instanceof Register) && (objs[1] instanceof Scalar));
                        Register r = (Register)objs[0];
                        Scalar s = (Scalar)objs[1];

                        strAddress = m_regStatus.get(r.getName());
                        strAddress = symbolicAdd(strAddress, s.getValue());

                        /* update memory access */
                        updateMemoryReadAccess(strAddress);

                        /* fetch the value from the memory elememt */
                        strValue = m_memStatus.get(strAddress);

                        /* upate register status */
                        updateRegister(oprd0, strValue);
                    }
                    else if (objs.length == 3) {
                        /* fix-me */
                        System.out.println("fix-me 491");
                    }

                    else {
                        /* Throw exception */
                        System.out.println("fix-me 530");
                        System.out.println("type value" + String.valueOf(oprd1ty));
                    }

                    /*for (Object o: dst) {
                        System.out.println(o.getClass().getSimpleName());
                        System.out.println(o.toString());
                    }*/
                }
            }
            else {
                System.out.println(inst.toString());
                /* Ghidra bug: MOV [RAX],RDX -> _, ADDR|REG */
                if (OPRDTYPE.isRegister(oprd1ty)) {
                    oprd1 = inst.getDefaultOperandRepresentation(1);
                    strVal1 = m_regStatus.get(oprd1);
                }
                else if (OPRDTYPE.isScalar(oprd1ty)){
                    oprd1 = inst.getDefaultOperandRepresentation(1);
                    strVal1 = oprd1;
                }
                else {
                    /* Throw exeception */
                    strVal1 = "";
                    System.out.println("fix-me 549");
                }

                objs = inst.getOpObjects(0);

                if (objs.length == 1) {
                    /* mov [reg], reg; mov [0x48000], 0x1234 */
                    if (objs[0] instanceof Register) {
                        Register r = (Register)objs[0];

                        /* update memory access */
                        strAddr0 = m_regStatus.get(r.getName());
                        updateMemoryWriteAccess(strAddr0, strVal1);
                    }
                    else if (objs[0] instanceof Scalar) {
                        Scalar s = (Scalar)objs[0];

                        /* update memory access */
                        strAddr0 = String.valueOf(s.getValue());
                        updateMemoryWriteAccess(strAddr0, strVal1);
                    }
                    else {
                        /* Throw exception */
                        System.err.println("fix-me 500");
                    }

                }
                else if (objs.length == 2) {
                    System.out.println(inst.toString());
                    /* Registet + Scaler: i.e [RBP + -0x28] */
                    assert((objs[0] instanceof Register) && (objs[1] instanceof Scalar));
                    Register r = (Register)objs[0];
                    Scalar s = (Scalar)objs[1];

                    /* update memory access */
                    strAddress = m_regStatus.get(r.getName());
                    strAddr0 = symbolicAdd(strAddress, s.getValue());
                    System.out.println("fix-me 591" + strAddr0 + strVal1);
                    updateMemoryWriteAccess(strAddr0, strVal1);
                }
                else if (objs.length == 3) {
                    /* fix-me */
                    System.out.println("fix-me 491");
                }

                else {
                    /* Throw exception */
                    System.out.println("fix-me 530");
                    System.out.println("type value" + String.valueOf(oprd1ty));
                }
            }
        }

        else {
            return;
        }
    }

    private boolean updateRegister(String reg, String value) {
        Set<String> tmpSet;

        /* Update MAR-table for Register reg */
        System.out.println("515:" + reg);
        tmpSet = m_smarTable.get(reg);
        if (tmpSet == null) {
            reg = m_arch.getRegisterFullname(reg);
            tmpSet = m_smarTable.get(reg);
        }
        assert(tmpSet != null);
        tmpSet.add(value);

        System.out.println("519:" + value);
        /* Update register status */
        m_regStatus.put(reg, value);

        return true;
    }

    private boolean updateMemoryWriteAccess(String address, String value) {
        Set<String> tmpSet;

        /* Update MAR-table for address */
        tmpSet = m_smarTable.get(address);
        if (tmpSet == null) {
            tmpSet = new HashSet<String>();
            m_smarTable.put(address, tmpSet);
        }
        tmpSet.add(value);

        /* Update memory status */
        m_memStatus.put(address, value);

        return true;
    }

    private boolean updateMemoryReadAccess(String address) {
        Set<String> tmpSet;

        /* Update MAR-table for address */
        tmpSet = m_smarTable.get(address);
        if (tmpSet == null) {
            String symbol;

            tmpSet = new HashSet<String>();
            m_smarTable.put(address, tmpSet);
            
            System.out.println("610:" + address);
            /* make the content of current address to a symbolic value */
            if (address.indexOf(' ') != -1) {
                symbol = String.format("V(%s)", address.replaceAll("\\s+",""));
            }
            else {
                symbol = "V" + address;
            }
            System.out.println("612:" + symbol);

            tmpSet.add(symbol);     // Set a symbolic value

            /* Update memory status */
            m_memStatus.put(address, symbol);
        }
        return true;
    }


    /* fix me */
    private String symbolicAdd(String symbol, long value) {
        return _symbolicAddSub(symbol, '+', value);
    }

    /* fix me */
    private String symbolicSub(String symbol, long value) {
        return _symbolicAddSub(symbol, '-', value);
    }

    private String _symbolicAddSub(String symbol, char op, long value) {
        /* parse the old symbolic value */
        String[] elems = symbol.split("\\s", 0);
        String sOprd = null;    // symbolic oprand
        long curValue = 0;

        if (elems.length == 1) {
            if (elems[0].charAt(0) != 'V') {
                curValue = Integer.parseInt(elems[0]);
            }
            else {
                sOprd = elems[0];
            }
        }
        else if (elems.length == 2) {
            curValue = Integer.parseInt(elems[1]);
            sOprd = elems[0];
        }
        else {
            /* Throw exception */
            System.err.println("Wrong format");
        }

        if (op == '+')
            curValue += value;
        else if (op == '-')
            curValue -= value;
        else /* Thow exception */
            System.err.println("Wrong format");


        /* generate new symbolic value */
        String newSymbol;
        long absValue ;

        absValue = Math.abs(curValue);
        if (sOprd == null) {
            newSymbol = String.format("%d", curValue);
        }
        else {
            if (curValue == 0)
                newSymbol = sOprd;
            else if (curValue > 0)
                newSymbol = String.format("%s +%d", sOprd, absValue);
            else
                newSymbol = String.format("%s -%d", sOprd, absValue);
        }

        return newSymbol;
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


interface HardwareArch {
    public String[] getRegisters();
    public String getRegisterFullname(String reg);
}

class LArchX86 implements HardwareArch {
    static final String [] m_Regs64 = {"RAX", "RBX", "RCX", "RDX", "RDI", "RSI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"};
    static final String [] m_Regs32 = {"EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D"};
    private Map<String, String> m_RegMap;

    LArchX86 () {
        m_RegMap = new HashMap<String, String>();

        int idx = 0;
        for (String r32: m_Regs32) {
            m_RegMap.put(r32, m_Regs64[idx]);
            idx++;
        }
    }

    public String[] getRegisters() {
        return m_Regs64;
    }

    public String getRegisterFullname(String reg) {
        return m_RegMap.get(reg);
    }
}
