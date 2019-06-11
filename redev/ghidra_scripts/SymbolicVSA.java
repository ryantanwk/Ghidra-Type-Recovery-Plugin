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

import javax.lang.model.util.ElementScanner6;

import java.lang.Math;
import java.lang.Object;

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
            if (fentry != 0x004005a6)
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

        m_registers = new HashMap<String, String>();        // CPU State : Registers
        m_memories = new HashMap<String, String>();         // CPU State : Memory slot
        m_SMARTable = new HashMap<String, Set<String>>();   // Symbolic Store
        m_blocks = new HashMap<Address, BlockSMAR>();       // Basic Blocks of this function

        /* get all registers */


        InitMachineStatus();
        InitSMARTable();
        constructCFG();
    }

    private void InitMachineStatus() {
        /* Set register values to symbolic initial values */
        String[] allRegs = m_arch.getAllRegisters();

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
        String[] allRegs = m_arch.getAllRegisters();

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

        // Should be a loop, if any symbolic state for any block has changed in the last round
        try {
            CodeBlock firstBlk = blkModel.getCodeBlockAt(addr, m_monitor);
            // Obtain the wrapper object for GHIDRA's basic block
            BlockSMAR smarBlk = m_blocks.get(firstBlk.getFirstStartAddress());

            //have_visited_bb_this_round [curr_bb] = False // For all basic blocks, set to false

            /* traverse all code-blocks recusively in depth-first search (DFS) order */
            smarBlk.traverseBlocksOnce(m_SMARTable, m_registers, m_memories);
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


    private Set<BlockSMAR> m_nexts;         // CFG Representation for a given function, stored as a list of succ. for a block
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

    /* traverse all code-blocks recusively */
    public boolean traverseBlocksOnce(Map<String, Set<String>> memory_access_table, HashMap<String, String> register_status, HashMap<String, String> memory_status) {
        /* Recording the state of the symbolic memory store at the start of the current code block */
        //is (new_memacc_table != existing_access_table) set_dirty (curr_bb);
        doRecording(memory_access_table, register_status, memory_status);

        //have_visited_bb_this_round [curr_bb] = True; //

        /* travers the next blocks in DFS order */
        if (m_nexts.size() >= 1) {
            for (BlockSMAR nextBlk: m_nexts) {
                //if (have_visited_bb_this_round) continue;

                // To remove
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

                    nextBlk.traverseBlocksOnce(memory_access_table, regs, mems);
                }
            }
        }
        return true;
    }


    String getRegValue(String register) {
        String reg, val;

        reg = m_arch.getRegisterFullname(register);
        return m_regStatus.get(reg);
    }


    String getMemValue(String address) {
        return m_memStatus.get(address);
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
                /* Throw exception */
                System.out.println("321: " + inst.toString());
                System.out.println("323: throw exception");
            }
        }
    }

    void _doRecording0(InstructionDB inst) {
        System.out.println("331: " + inst.toString());
        String op = inst.getMnemonicString();

        if(op.equalsIgnoreCase("nop")) {
            return;
        }

        if(op.equalsIgnoreCase("ret")) {
            _record0ret(inst);
        }

        else if(op.equalsIgnoreCase("leave")) {
            _record0leave(inst);
        }

        else {
            System.out.println("333: fix-me, other instructions");
        }
    }

    private void _record0ret(InstructionDB inst) {
        /* pop rip */
        String strValue;
        /* Update RSP register status */
        strValue = getRegValue("RSP");
        strValue = symbolicAdd(strValue, 8);
        updateRegister("RSP", strValue);
    }

    private void _record0leave(InstructionDB inst) {
        /* mov rsp, rbp; pop rbp */
        String strValSP, strValBP;
        String strValue;

        /* mov rsp, rbp */
        strValBP = getRegValue("RBP");
        updateRegister("RSP", strValBP);

        /* pop rbp */
        strValSP = getRegValue("RSP");
        strValue = getMemValue(strValSP);
        updateRegister("RBP", strValue);

        /* Clean memory status */
        strValSP = getRegValue("RSP");
        m_memStatus.remove(strValSP);

        /* Update register RSP */
        strValSP = getRegValue("RSP");
        strValue = symbolicAdd(strValSP, 8);
        updateRegister("RSP", strValue);
    }


    void _doRecording1(InstructionDB inst) {
        System.out.println("340: " + inst.toString());

        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

        String op = inst.getMnemonicString();

        if(op.equalsIgnoreCase("push")) {
            _record1push(inst);
        }

        else if (op.equalsIgnoreCase("pop")) {
            _record1pop(inst);
        }

        else if (op.equalsIgnoreCase("call")) {
            /* call xxx */
            System.out.println("400: fix-me, call xxx");
        }
        else if (op.charAt(0) == 'j' || op.charAt(0) == 'J' ) {
            /* jump xxx & jcc xx */
            System.out.println("405: fix-me, jxx");
        }
        else if (op.equalsIgnoreCase("ret")) {
            /* retn 0x8 */
            _record1retn(inst);
        }

        else {
            System.out.println("387: fix-me, other instruction");
        }
    }

    private void _record1push(InstructionDB inst) {
        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

        /* push reg; push 0x1234; */
        String oprd = inst.getDefaultOperandRepresentation(0);
        int oprdty = inst.getOperandType(0);

        /* Get oprand value & upadte MAR-table */
        if (OPRDTYPE.isRegister(oprdty)) { // register
            strValue = getRegValue(oprd);
        }
        else if (OPRDTYPE.isScalar(oprdty)){ // Constant value
            strValue = oprd;
        }
        else { // must be address: two memory oprand does't supported by x86 and ARM
            System.out.println("326: throw exception, Wrong operand");
        }

        /* Update MAR-table & register status */
        strAddr = getRegValue("RSP");
        strAddr = symbolicSub(strAddr, 8);
        updateRegister("RSP", strAddr);

        /* Update MAR-table & memory status */
        strAddr = getRegValue("RSP");
        updateMemoryWriteAccess(strAddr, strValue);
    }

    private void _record1pop(InstructionDB inst) {
        String strAddr = null;
        String strValue = null;
        Set<String> tmpSet = null;

        /* pop reg */
        String oprd = inst.getDefaultOperandRepresentation(0);
        int oprdty = inst.getOperandType(0);

        /* operand must be a reigster. Other type of memory access does't supported by x86 and ARM  */
        assert(OPRDTYPE.isRegister(oprdty));

        // strAddr = getRegValue("RSP");
        // updateMemoryReadAccess(strAddr);

        /* Get value from stack && update rigister status */
        strValue = getRegValue("RSP");
        strValue = getMemValue(strValue);
        updateRegister(oprd, strValue);

        /* Clean memory status */
        strValue = getRegValue("RSP");
        m_memStatus.remove(strValue);

        /* Update RSP register status */
        strValue = getRegValue("RSP");
        strValue = symbolicAdd(strValue, 8);
        updateRegister("RSP", strValue);
    }

    private void _record1retn(InstructionDB inst) {
        String strValue,  strValSP, oprd;

        oprd = inst.getDefaultOperandRepresentation(0);

        /* Update RSP register status */
        strValSP = getRegValue("RSP");
        strValue = symbolicAdd(strValSP, Integer.decode(oprd) + 8);
        updateRegister("RSP", strValue);
    }

    void _doRecording2(InstructionDB inst) {
        System.out.println("414: " + inst.toString());

        String op = inst.getMnemonicString();

        if (op.equalsIgnoreCase("add")) {
            /* sub reg, reg; sub reg, 0x1234; sub reg, mem; sub mem, reg; sub mem, 0x1234 */
            _record2addsub(inst, '+');
        }

        else if (op.equalsIgnoreCase("sub")) {
            _record2addsub(inst, '-');
        }

        else if (op.equalsIgnoreCase("mov")) {
            _record2mov(inst);
        }

        else if (op.equalsIgnoreCase("movss")) {
            _record2mov(inst);
        }

        else if (op.equalsIgnoreCase("lea")) {
            _record2lea(inst);
        }

        else if (op.equalsIgnoreCase("xor")) {
            _record2xor(inst);
        }

        else {
            System.out.println("347: fix-me");
        }
    }

    private void _record2addsub(InstructionDB inst, char op) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        if (OPRDTYPE.isRegister(oprd0ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            strVal0 = getRegValue(oprd0);

            if (OPRDTYPE.isRegister(oprd1ty)) {
                /* sub reg, reg */
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegValue(oprd1);

                if (op == '+')
                    strValue = symbolicAdd(strVal0, strVal1);
                else if (op == '-')
                    strValue = symbolicSub(strVal0, strVal1);
                else
                    strValue = strVal0; //fix-me

                updateRegister(oprd0, strValue);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                /* sub rsp, 8; */
                oprd1 = inst.getDefaultOperandRepresentation(1);

                if (op == '+')
                    strValue = symbolicAdd(strVal0, Integer.decode(oprd1));
                else if (op == '-')
                    strValue = symbolicSub(strVal0, Integer.decode(oprd1));
                else
                    strValue = strVal0;

                /* upate register status */
                updateRegister(oprd0, strValue);
            }
            else {
                /* others */
                objs = inst.getOpObjects(1);

                strAddr1 = _getMemAddress(objs);

                /* update memory read access */
                updateMemoryReadAccess(strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemValue(strAddr1);


                if (op == '+')
                    strValue = symbolicAdd(strVal0, strVal1);
                else if (op == '-')
                    strValue = symbolicSub(strVal0, strVal1);
                else
                    strValue = strVal0;

                /* upate register status */
                updateRegister(oprd0, strValue);
            }
        }
        else {
            /* The first operand is in memory */
            /* Ghidra bug: sub [RAX],RDX -> _, ADDR|REG */
            if (OPRDTYPE.isRegister(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegValue(oprd1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            }
            else {
                /* Throw exeception */
                strVal1 = "";
                System.out.println("549: throw exception");
            }

            objs = inst.getOpObjects(0);
            strAddr0 = _getMemAddress(objs);

            /* fetch the value from the memory elememt */
            strVal0 = getMemValue(strAddr0);

            if (op == '+')
                strValue = symbolicAdd(strVal0, strVal1);
            else if (op == '-')
                strValue = symbolicSub(strVal0, strVal1);
            else
                strValue = strVal0;

            /* update memory write access */
            updateMemoryWriteAccess(strAddr0, strValue);
        }
    }


    private void _record2mov(InstructionDB inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* mov reg, reg; mov reg, mem; mov reg, 0x1234; mov mem, reg; mov mem, 0x1234 */
        if (OPRDTYPE.isRegister(oprd0ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            if (OPRDTYPE.isRegister(oprd1ty)) {
                /* mov reg, reg */
                oprd1 = inst.getDefaultOperandRepresentation(1);

                strVal1  = getRegValue(oprd1);
                updateRegister(oprd0, strVal1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                /* mov rax, 8; */
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;

                /* upate register status */
                updateRegister(oprd0, strVal1);
            }
            else { /* memory oprand */
                objs = inst.getOpObjects(1);
                strAddr1 = _getMemAddress(objs);

                /* update memory read access */
                updateMemoryReadAccess(strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemValue(strAddr1);

                /* upate register status */
                updateRegister(oprd0, strVal1);
            }
        }
        else {
            /* Ghidra bug: MOV [RAX],RDX -> _, ADDR|REG */
            if (OPRDTYPE.isRegister(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegValue(oprd1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            }
            else {
                /* Throw exeception */
                strVal1 = "";
                System.out.println("600: throw exception");
            }

            objs = inst.getOpObjects(0);

            strAddr0 = _getMemAddress(objs);

            /* update memory write access */
            updateMemoryWriteAccess(strAddr0, strVal1);
        }
    }


    private void _record2lea(InstructionDB inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* get the name of register */
        assert(OPRDTYPE.isRegister(oprd0ty));
        oprd0 = inst.getDefaultOperandRepresentation(0);

        /* get the value of second operand */
        objs = inst.getOpObjects(1);
        strAddr1 = _getMemAddress(objs);
        strValue = strAddr1;

        /* upate register status */
        updateRegister(oprd0, strValue);
    }


    private void _record2xor(InstructionDB inst) {
        int oprd0ty = inst.getOperandType(0);
        int oprd1ty = inst.getOperandType(1);

        String strVal0, strVal1, strAddr0, strAddr1;
        String strValue, strAddress;
        String oprd0, oprd1;
        long iVal0, iVal1;

        Object[] objs;

        /* mov reg, reg; mov reg, mem; mov reg, 0x1234; mov mem, reg; mov mem, 0x1234 */
        if (OPRDTYPE.isRegister(oprd0ty)) {
            oprd0 = inst.getDefaultOperandRepresentation(0);
            strVal0  = getRegValue(oprd0);
            if (OPRDTYPE.isRegister(oprd1ty)) {
                /* xor reg, reg */
                oprd1 = inst.getDefaultOperandRepresentation(1);

                strVal1  = getRegValue(oprd1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                /* mov rax, 8; */
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            }
            else { /* memory oprand */
                objs = inst.getOpObjects(1);
                strAddr1 = _getMemAddress(objs);

                /* update memory read access */
                updateMemoryReadAccess(strAddr1);

                /* fetch the value from the memory elememt */
                strVal1 = getMemValue(strAddr1);
            }

            System.out.println("754: " + strVal1);
            /* upate register status */
            strValue = symbolicXor(strVal0, strVal1);
            updateRegister(oprd0, strValue);
        }
        else {
            /* Ghidra bug: MOV [RAX],RDX -> _, ADDR|REG */
            if (OPRDTYPE.isRegister(oprd1ty)) {
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = getRegValue(oprd1);
            }
            else if (OPRDTYPE.isScalar(oprd1ty)){
                oprd1 = inst.getDefaultOperandRepresentation(1);
                strVal1 = oprd1;
            }
            else {
                /* Throw exeception */
                strVal1 = "";
                System.out.println("770: throw exception");
            }

            objs = inst.getOpObjects(0);

            strAddr0 = _getMemAddress(objs);

            /* update memory read access */
            updateMemoryReadAccess(strAddr0);

            /* fetch the value from the memory elememt */
            strVal0 = getMemValue(strAddr0);
            /* update memory write access */
            strValue = symbolicXor(strVal0, strVal1);

            updateMemoryWriteAccess(strAddr0, strValue);
        }
    }


    private String _getMemAddress(Object[] objs_of_MemOperand) {
        /* A memory oprand from Ghidra, consits with an array of objects */
        Object[] objs = objs_of_MemOperand;
        String strValue, strAddress;

        if (objs.length == 1) {
            /* mov reg, [reg]; mov reg, [0x48000] */
            if (objs[0] instanceof Register) {
                Register r = (Register)objs[0];

                /* get regiser value */
                strValue = getRegValue(r.getName());
                return strValue;
            }
            else if (objs[0] instanceof Scalar) {
                Scalar s = (Scalar)objs[0];

                /* get memory address */
                strAddress = String.valueOf(s.getValue());
                return strAddress;

            }
            else if (objs[0] instanceof GenericAddress) {
                GenericAddress a = (GenericAddress)objs[0];

                strAddress = String.valueOf(a.getOffset());
                return strAddress;
            }

            else {
                /* Throw exception */
                System.err.println("850: throw exception");
                System.err.println("849: " + objs[0].getClass().getName());

                return "";
            }
        }
        else if (objs.length == 2) {
            /* Registet + Scaler: i.e [RBP + -0x28] */
            assert((objs[0] instanceof Register) && (objs[1] instanceof Scalar));
            Register r = (Register)objs[0];
            Scalar s = (Scalar)objs[1];

            strValue = getRegValue(r.getName());
            strAddress = symbolicAdd(strValue, s.getValue());

            return strAddress;
        }
        else if (objs.length == 3) {
            /* fix-me */
            System.out.println("875: fix-me");
            return "";
        }

        else {
            /* Throw exception */
            System.out.println("880: throw exception");

            /* print some details */
            for (Object o: objs) {
                System.out.println("885: " + o.getClass().getName());
            }
            return "";
        }
    }

    private boolean updateRegister(String reg, String value) {
        Set<String> tmpSet;

        /* Update MAR-table for Register reg */
        tmpSet = m_smarTable.get(reg);
        if (tmpSet == null) {
            reg = m_arch.getRegisterFullname(reg);
            tmpSet = m_smarTable.get(reg);
        }
        assert(tmpSet != null);
        tmpSet.add(value);

        /* for debugging */
        System.out.println(String.format("674: %s = %s", reg, value));

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

        /* for debuging */
        System.out.println(String.format("686: [%s] = %s", address, value));

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

            /* make the content of current address to a symbolic value */
            if (address.indexOf(' ') != -1) {
                symbol = String.format("V(%s)", address.replaceAll("\\s+",""));
            }
            else {
                symbol = "V" + address;
            }
            tmpSet.add(symbol);     // Set a symbolic value

            /* Update memory status */
            m_memStatus.put(address, symbol);
        }
        return true;
    }


    private String symbolicAdd(String symbol, long value) {
        return _symbolicAddSub(symbol, '+', value);
    }


    private String symbolicSub(String symbol, long value) {
        return _symbolicAddSub(symbol, '-', value);
    }

    private String symbolicAdd(String symbol0, String symbol1) {
        /* fix-me */
        return symbol0;
    }

    private String symbolicSub(String symbol0, String symbol1) {
        /* fix-me */
        return symbol0;
    }


    private String _symbolicAddSub(String symbol, char op, long value) {
        /* parse the old symbolic value */
        String[] elems = symbol.split("\\s", 0);
        String sOprd = null;    // symbolic oprand
        long curValue = 0;

        if (elems.length == 1) {
            if (elems[0].charAt(0) != 'V' && elems[0].charAt(0) != 'D') {
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
            System.out.println("779: throw exception, wrong format");
        }

        if (op == '+')
            curValue += value;
        else if (op == '-')
            curValue -= value;
        else /* Thow exception */
            System.out.println("787: throw exception, Wrong format");


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



    String symbolicMul(String symbol, long value) {
        /* fix me */
        System.out.println("814: fix-me");
        return symbol + "x" + String.valueOf(value);
    }


    String symbolicDiv(String symbol, long value) {
        System.out.println("820: fix-me");
        return symbol + "/" + String.valueOf(value);
    }


    String symbolicXor(String symbol0, String symbol1) {
        String val0 = symbol0.strip();
        String val1 = symbol1.strip();
        String value;

        if (val0 == val1) {
            value = "0";
        }
        else {
            System.out.println(String.format("%s %s", val0.replaceAll("\\s+",""), val1.replaceAll("\\s+","")));
            value = String.format("D%s^%s", val0.replaceAll("\\s+",""), val1.replaceAll("\\s+",""));
        }

        return value;
    }


    int getRunCount() {
        return m_runs;
    }
}


interface HardwareArch {
    public String[] getAllRegisters();
    public String getRegisterFullname(String reg);
}


class LArchX86 implements HardwareArch {
    static final String [] m_Regs64 = {"RAX", "RBX", "RCX", "RDX", "RDI", "RSI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"};
    static final String [] m_Regs32 = {"EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D"};
    static final String [] m_Regs16 = {"AX", "BX", "CX", "DX", "DI", "SI", "BP", "SP"};
    static final String [] m_Regs8h = {"AH", "BH", "CH", "DH"};
    static final String [] m_Regs8l = {"AL", "BL", "CL", "DL"};
    static final String [] m_RegSeg = {"FS", "GS"};
    static final String [] m_RegXmm = {"XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7"};

    private Map<String, String> m_RegMap;
    private String[] m_AllRegs;


    LArchX86 () {
        m_RegMap = new HashMap<String, String>();

        int idx = 0;

        for (idx = 0; idx < m_RegSeg.length; idx++) {
            m_RegMap.put(m_RegSeg[idx], m_RegSeg[idx]);
        }

        for (idx = 0; idx < m_RegXmm.length; idx++) {
            m_RegMap.put(m_RegXmm[idx], m_RegXmm[idx]);
        }

        for (idx = 0; idx < m_Regs64.length; idx++) {
            m_RegMap.put(m_Regs64[idx], m_Regs64[idx]);
        }

        for (idx = 0; idx < m_Regs32.length; idx++) {
            m_RegMap.put(m_Regs32[idx], m_Regs64[idx]);
        }

        for (idx = 0; idx < m_Regs16.length; idx++) {
            m_RegMap.put(m_Regs16[idx], m_Regs64[idx]);
        }

        for (idx = 0; idx < m_Regs8h.length; idx++) {
            m_RegMap.put(m_Regs8h[idx], m_Regs64[idx]);
        }

        for (idx = 0; idx < m_Regs8l.length; idx++) {
            m_RegMap.put(m_Regs8l[idx], m_Regs64[idx]);
        }
    }

    /* Get all kinds of registers of this platform */
    public String[] getAllRegisters() {

        if (m_AllRegs == null) {
            String[] allRegs = new String[m_RegSeg.length + m_RegXmm.length + m_Regs64.length];

            System.arraycopy(m_RegSeg, 0, allRegs, 0, m_RegSeg.length);
            System.arraycopy(m_RegXmm, 0, allRegs, m_RegSeg.length, m_RegXmm.length);
            System.arraycopy(m_Regs64, 0, allRegs, m_RegSeg.length+m_RegXmm.length, m_Regs64.length);
            m_AllRegs = allRegs;
        }

        return m_AllRegs;
    }


    public String getRegisterFullname(String reg) {
        return m_RegMap.get(reg);
    }
}
