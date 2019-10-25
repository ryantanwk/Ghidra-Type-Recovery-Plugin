
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
import java.util.*; // Map & List

import java.lang.Math;
import java.lang.Object;
import java.math.BigInteger;
import java.text.DecimalFormat;

import ghidra.program.model.listing.*;
import ghidra.program.model.block.*; //CodeBlock && CodeBlockImpl
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.Language;
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

public class VSA_IR extends GhidraScript {
    private Program program;
    private Listing listing;
    private Language language;

    /**
     * Calculate the address space of code segments
     *
     * @return return null if failed
     */
    AddressSet getCodeAddresRange() {
        MemoryBlock[] blocks;
        Address addrStart, addrEnd;
        Address addrStartF, addrEndF;
        long vmStart, vmEnd;

        blocks = program.getMemory().getBlocks();
        vmStart = 10; // vmStart = (unsigned long) -1
        vmEnd = 0;
        addrStartF = null;
        addrEndF = null;

        boolean bFind = false;
        for (MemoryBlock blk : blocks) {
            /*
             * An ELF file always has several code sections. If yes, we assume they are
             * layed continuously
             */
            if (!(blk.isExecute() && blk.isInitialized() && blk.isLoaded()))
                continue;

            addrStart = blk.getStart();
            addrEnd = blk.getEnd();

            if (vmStart > vmEnd) { // This means we find the first code section
                vmStart = addrStart.getOffset();
                vmEnd = addrEnd.getOffset();
                addrStartF = addrStart;
                addrEndF = addrEnd;

                bFind = true;
                continue;
            }

            /* considering code alignment, default to 16 bytes */
            if (vmEnd < addrEnd.getOffset() && addrStart.getOffset() <= (vmEnd + 15 >> 4 << 4)) {
                vmEnd = addrEnd.getOffset();
                addrEndF = addrEnd;

            } else {
                /* warning ? */
                String msg = String.format("310: Non-continuous section: %s: 0x%x - 0x%x", blk.getName(),
                        addrStart.getOffset(), addrEnd.getOffset());
                println(msg);
            }
        }

        if (!bFind) {
            String msg = String.format("Faile to find code segment");
            println(msg);

            return null;
        } else {
            return new AddressSet(addrStartF, addrEndF);
        }
    }

    @Override
    public void run() {
        program = state.getCurrentProgram();
        listing = program.getListing();
        language = program.getLanguage();

        VSADataTypeManager dtMgr = VSADataTypeManager.getInstance(program);

        /* travese all functions */
        AddressSet codesegRng = getCodeAddresRange();
        if (codesegRng == null) {
            return;
        }

        FunctionIterator iter = listing.getFunctions(true);
        Address startVM = codesegRng.getMinAddress();
        Address endVM = codesegRng.getMaxAddress();
        
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            String fname = f.getName();
            Address f_startVM, f_endVM;

            f_startVM = f.getBody().getMinAddress();
            f_endVM = f.getBody().getMaxAddress();

            /* skip all functions out the address space of current segment */
            if (f_startVM.getOffset() < startVM.getOffset() || f_endVM.getOffset() > endVM.getOffset())
                continue;

            // Entry-point
            // if (f.getEntryPoint().getOffset() != 0x0400546)
            //     continue;

            String info = String.format("Function: name: %s entry: %s", f.getName(), f.getEntryPoint());
            println(info);

            FunctionSMAR smar = new FunctionSMAR(program, listing, f, monitor);
            smar.doSMARecording(); // START VSA

            Map<Long, Map<String, Set<String>>> smart = smar.getSMARTable();
            if (smart.size() > 0) {
                println("SMARTable: " + smart.toString());
            }

            DataAccessAnalysis analyzer = new DataAccessAnalysis(smart);

            Set<String> array_info = analyzer.inferArrayAccess();
            if (array_info.size() > 0) {
                println("Possible arrays: " + array_info.toString());
            }

            Map<String, List<Long>> struct_access = analyzer.inferStructAccess();
            if (struct_access.size() > 0) {
                println("Possible structs: " + struct_access.toString());
            }

            SystemVLinux64Parameter param_updater = new SystemVLinux64Parameter(program);
            Set<String> params = param_updater.inferActiveParameters(smart);
            if (params.size() > 0) {
                println("Number of parameters inuse: " + String.valueOf(params.size()));
            }

            Map<String, DataType> vsa_structs = dtMgr.inferDataStructs(struct_access);
            param_updater.updateParameters(f, vsa_structs);
        }
    }
}

class VSADataTypeManager {
    private static VSADataTypeManager m_singleton;
    private DataTypeManager m_dataMgr;

    private VSADataTypeManager(Program program) {
        m_dataMgr = program.getDataTypeManager();
    }

    public static VSADataTypeManager getInstance(Program program) {
        if (m_singleton == null) {
            m_singleton = new VSADataTypeManager(program);
        }
        return m_singleton;
    }

    /**
     * Get a data structure generated by SymbolicVSA according to its data layout
     *
     * @param struct_layout
     * @return retrun null if failed
     */
    private DataType inferDataStruct(List<Long> struct_layout) {
        String struct_name = String.format("VSA%d", struct_layout.size());

        /* Generate struct name */
        for (int i = 1; i < struct_layout.size(); i++) {
            int delta = (int) (struct_layout.get(i) - struct_layout.get(i - 1));

            switch (delta) {
            case 1:
                struct_name += "B";
                break;
            case 2:
                struct_name += "W";
                break;
            case 4:
                struct_name += "D";
                break;
            case 8:
                struct_name += "Q";
                break;
            default:
                String msg = String.format("Failed to parse data layout %d @ %s", delta, struct_layout.toString());
                System.err.println(msg);
                return null;
            }
        }

        /* Set the last field to INT */
        struct_name += "D";

        DataType dt = m_dataMgr.getDataType(struct_name);
        if (dt != null)
            return dt;

        /* else: Create a new structure */
        List<DataType> fields = new ArrayList<>();

        for (int i = 1; i < struct_layout.size(); i++) {
            int delta = (int) (struct_layout.get(i) - struct_layout.get(i - 1));

            switch (delta) {
            case 1:
                fields.add(ByteDataType.dataType);
                break;
            case 2:
                // fields.add(WordDataType.dataType);
                fields.add(ShortDataType.dataType);
                break;
            case 4:
                // fields.add(DWordDataType.dataType);
                fields.add(IntegerDataType.dataType);
                break;
            case 8:
                // fields.add(QWordDataType.dataType);
                fields.add(LongDataType.dataType);
                break;
            default:
                throw new IllegalArgumentException("Failed to parse data layout");
                // break;
            }
        }
        /* Set the last field to INT */
        fields.add(IntegerDataType.dataType);

        /* Create a new structure */
        Structure st = new StructureDataType(struct_name, 0);

        for (int i = 0; i < fields.size(); i++) {
            String fldname = String.format("data%d", i);
            st.add(fields.get(i), fldname, null);
        }
        m_dataMgr.addDataType(st, null);

        return st;
    }

    public Map<String, DataType> inferDataStructs(Map<String, List<Long>> possilbe_structs) {
        Map<String, DataType> mapScope2DT = new HashMap<>(); // map a scope name to a datatype;

        for (Map.Entry<String, List<Long>> entmapStruct : possilbe_structs.entrySet()) {
            String scope = entmapStruct.getKey();
            DataType dt = inferDataStruct(entmapStruct.getValue());

            if (dt != null) {
                mapScope2DT.put(scope, dt);
            }
        }

        return mapScope2DT;
    }
}

interface VSAParameterAnalyzer {
    public Set<String> inferActiveParameters(Map<Long, Map<String, Set<String>>> symbolic_memory_access_table);

    public void updateParameters(Function function, Map<String, DataType> vsa_structs);
}

/**
 *
 */
class MicrosoftWindows64Parameter implements VSAParameterAnalyzer {
    public Set<String> inferActiveParameters(Map<Long, Map<String, Set<String>>> symbolic_memory_access_table) {
        return null;
    }

    public void updateParameters(Function function, Map<String, DataType> vsa_structs) {
    }
}

// class SystemVLinux64Parameter implements VSAParameterAnalyzer {
class SystemVLinux64Parameter {
    private Program m_program;

    private Set<String> m_setAllScopes;
    private Map<String, DataType> m_mapScopeDT; // map a scope name to a datatype;

    /* General purpose registers maybe used for passing parameters */
    final static String[] m_regGNames = new String[] { "RDI", "RSI", "RDX", "RCX", "R8", "R9" };

    /* Float-point registers maybe used for passing parameters */
    final static String[] m_regFNames = new String[] { "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
            "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15" };

    public SystemVLinux64Parameter(Program program) {
        m_program = program;
    }

    /**
     * RDI, RSI, RDX, RCX, R8, R9, XMM0–7
     */
    public Set<String> inferActiveParameters(Map<Long, Map<String, Set<String>>> symbolic_memory_access_table) {
        Set<String> setAllValues = new HashSet<>();

        for (Map.Entry<Long, Map<String, Set<String>>> entMapSMAT : symbolic_memory_access_table.entrySet()) {
            Map<String, Set<String>> mapVS = entMapSMAT.getValue();

            /* memory accessed by this function */
            for (Map.Entry<String, Set<String>> entMapVS : mapVS.entrySet()) {
                Set<String> vs = entMapVS.getValue();

                for (String val : vs) {
                    /* Collect symbolic values only */
                    if (val.length() < 0 || val.charAt(0) != 'V')
                        continue;

                    setAllValues.add(val);
                }
            }
        }

        Set<String> params = new HashSet<>();

        try {
            /* for general purpose registers */
            for (int i = 0; i < m_regGNames.length; i++) {
                String scope = "V" + m_regGNames[i];
                if (setAllValues.contains(scope)) {
                    params.add(m_regGNames[i]);
                }
            }

            /* for float-point registers */
            for (int i = 0; i < m_regFNames.length; i++) {
                String scope = "V" + m_regFNames[i];

                if (setAllValues.contains(scope)) {
                    params.add(m_regFNames[i]);
                }
            }
        }

        catch (Exception e) {
            String fname = e.getStackTrace()[0].getFileName();
            int line = e.getStackTrace()[0].getLineNumber();
            System.err.println(String.format("%s:%d: %s", fname, line, e.toString()));
        }
        return params;
    }

    /***
     *
     * @param memory_scopes
     * @param reg
     * @param dt
     * @param name
     * @return return null if failed
     */
    private Variable _genRegParameter(String reg_name, DataType dt, String param_name) {
        /* Create a variable if possible */
        Variable parameter = null;

        try {
            Register register = m_program.getProgramContext().getRegister(reg_name);
            PointerDataType pdt = new PointerDataType(dt);

            parameter = new ParameterImpl(param_name, pdt, register, m_program);
        } catch (Exception e) {
            parameter = null;

            String fname = e.getStackTrace()[0].getFileName();
            int line = e.getStackTrace()[0].getLineNumber();
            System.err.println(String.format("%s:%d: %s", fname, line, e.toString()));
        }

        return parameter;
    }

    private Variable genGPRParameter(String reg_name, DataType dt, int ordinal) {
        String param_name = "GP" + String.valueOf(ordinal);

        /* IntegerDataType.dataType is the default data type */
        if (dt != null) {
            return _genRegParameter(reg_name, dt, param_name);
        } else {
            return null;
        }
    }

    private Variable genFPRParameter(String reg_name, DataType dt, int ordinal) {
        String param_name = "FP" + String.valueOf(ordinal);

        /* FloatDataType.dataType is the default data type */
        if (dt != null) {
            return _genRegParameter(reg_name, dt, param_name);
        } else {
            return null;
        }
    }

    /**
     *
     * @param function
     * @param structs  symbolic-VSA result, a mapping from SCOPE to Datatype
     * @return
     */
    public void updateParameters(Function function, Map<String, DataType> vsa_structs) {
        List<Variable> params = new ArrayList<>();
        Set<String> setScope = vsa_structs.keySet();
        int ordinal = 0;

        try {
            /* for general purpose registers */
            for (int i = 0; i < m_regGNames.length; i++) {
                String reg_name = m_regGNames[i];
                String this_scope = "V" + reg_name;

                if (!setScope.contains(this_scope))
                    break;

                DataType dt = vsa_structs.get(this_scope);
                Variable p = genGPRParameter(m_regGNames[i], dt, ordinal);
                if (p != null) {
                    params.add(p);
                    ordinal++;
                } else {
                    break;
                }
            }

            /* for float-point registers */
            for (int i = 0; i < m_regFNames.length; i++) {
                String reg_name = m_regFNames[i];
                String this_scope = "V" + reg_name;
                if (!setScope.contains(this_scope))
                    break;

                DataType dt = vsa_structs.get(this_scope);
                Variable p = genFPRParameter(m_regFNames[i], dt, ordinal);
                if (p != null) {
                    params.add(p);
                    ordinal++;
                } else {
                    break;
                }
            }

            int nParams = function.getParameterCount();
            if (params.size() > 0 && params.size() == nParams) {
                // f.replaceParameters(params, Function.FunctionUpdateType.CUSTOM_STORAGE,
                // false, SourceType.USER_DEFINED);
                function.updateFunction(null, null, params, Function.FunctionUpdateType.CUSTOM_STORAGE, false,
                        SourceType.USER_DEFINED);
            }
        }

        catch (Exception e) {
            String fname = e.getStackTrace()[0].getFileName();
            int line = e.getStackTrace()[0].getLineNumber();
            System.err.println(String.format("%s:%d: %s", fname, line, e.toString()));
        }
    }
}

/*----------------------------copy from FunctionSMAR.java-------------------------------------------------------------------*/
/*
 * Function-level symbolic memory access recording (SMAR) Every symbolic value
 * defines a domain
 */
class FunctionSMAR {
    private final Program m_program;
    private final Listing m_listDB;
    private final Function m_function;
    private TaskMonitor m_monitor;

    private Map<Address, ExecutionBlock> m_blocks; // All blocks in this function

    public FunctionSMAR(Program program, Listing listintDB, Function function, TaskMonitor monitor) {
        m_program = program;
        m_listDB = listintDB;
        m_function = function;
        m_monitor = monitor;

        constructCFG();
    }

    /**
     * Construct the CFG for all basic blocks
     */
    private void constructCFG() {
        if (m_blocks == null)
            m_blocks = new HashMap<>(); // Basic Blocks of this function

        try {
            /* Create ExecutionBlock for each Ghidra's codeblock */
            CodeBlockModel blkModel = new BasicBlockModel(m_program);
            AddressSetView addrSV = m_function.getBody();
            CodeBlockIterator codeblkIt = blkModel.getCodeBlocksContaining(addrSV, m_monitor);

            while (codeblkIt.hasNext()) {
                CodeBlock codeBlk = codeblkIt.next();
                ExecutionBlock smarBlk = new ExecutionBlock(m_listDB, m_function, codeBlk, m_program);
                Address addrStart = codeBlk.getFirstStartAddress();
                m_blocks.put(addrStart, smarBlk);
            }
        } catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("Failed to obtain Ghidra's basic blocks @ " + m_function.getName());
        }

        try {
            /* Create control-flow graph */
            for (ExecutionBlock curSMARBlk : m_blocks.values()) {
                /* find the next-blocks of current code-block */
                Set<ExecutionBlock> nxtSMARblks = new HashSet<>();
                CodeBlock curCodeBlk = curSMARBlk.getCodeBlock();
                CodeBlockReferenceIterator di = curCodeBlk.getDestinations(m_monitor);
                while (di.hasNext()) {
                    CodeBlockReference ref = di.next();
                    CodeBlock nxtCodeBlk = ref.getDestinationBlock();
                    Address addrStart = nxtCodeBlk.getFirstStartAddress();
                    ExecutionBlock nxtSMARBlk = m_blocks.get(addrStart);
                    if (nxtSMARBlk != null) {
                        nxtSMARblks.add(nxtSMARBlk);
                    }
                }

                /* set the m_next filed of current SMARTblock */
                curSMARBlk.setSuccessor(nxtSMARblks);
            }
        } catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("Failed to contruct the CFG for function " + m_function.getName());
        }
    }

    /**
     * Do symbolic memory access recording for current function. Apply the VSA
     * algorithm.
     *
     * @return
     */
    public boolean doSMARecording() {
        /* Obtain the wrapper object for GHIDRA's basic block */
        Address fentry = m_function.getEntryPoint();
        ExecutionBlock firstBlk = m_blocks.get(fentry);
        if (firstBlk == null) {
            throw new NullPointerException("Cannot get the first block");
        }

        /* Initialize the Machine state */
        IRInterpreter inpt = IRInterpreter.getInterpreter(m_program);
        MachineState init_state = MachineState.createInitState();
        firstBlk.setInitMachState(init_state);

        try {
            /* loop until no changes to symbolic state */
            ExecutionBlock smarBlk;
            while (true) {
                /* pick up a block which has Machine-state to run? */
                smarBlk = null;
                for (ExecutionBlock blk : m_blocks.values()) {
                    int nState = blk.getNumOfMachState();
                    boolean bDirty = blk.isSMRTDirty();

                    if (nState > 0 && bDirty) {
                        smarBlk = blk;
                        break;
                    }
                }

                /* end loop 8 */
                if (smarBlk == null)
                    break;

                /* smarBlk != null */
                traverseBlocksOnce(smarBlk);
            }
        } catch (Exception e) {
            /* fixe-me: ignore current function */
            System.err.println("272: Failed to traversBlocks: " + e.toString());
        }
        return true;
    }

    /**
     * traverse all code-blocks recusively in depth-first search (DFS) order
     *
     * @param start_block: The block for starting traversing
     * @return
     */
    private boolean traverseBlocksOnce(ExecutionBlock start_block) {
        /* set all blocks un-visted */
        for (ExecutionBlock blk : m_blocks.values()) {
            blk.m_bVisted = false;
        }

        start_block.runCFGOnce();
        return true;
    }

    /**
     * Fetch SMART from each SMARBlock.
     *
     * @return : the SMAR-table
     */
    public Map<Long, Map<String, Set<String>>> getSMARTable() {
        SMARTable SMARTable = new SMARTable(); // Symbolic Store

        /* fetch SMART from each block */
        Map<Long, Map<String, Set<String>>> smart;

        for (ExecutionBlock blk : m_blocks.values()) {
            smart = blk.getSMARTable();

            if (smart != null)
                SMARTable.putAll(smart);
        }
        return SMARTable.m_tbl;
    }
}

/*
 * Basic block Representation for a given function, a wrapper of Ghidra's basic
 * block
 */
class SMARBlock {
    private Listing m_listDB;
    private CodeBlock m_block; // Ghidra's basic block

    private AddressSet m_addrSet; // The address space convering this block

    public boolean m_dirtySMART; // The SMRT table is diry, means current block needs a new round of recording if
                                 // also have MachineState

    IRInterpreter m_inpt;

    /*
     * Each basic block has its own SMARTable, used for storing memory access record
     */
    SMARTable m_smarTable;

    public SMARBlock(Listing listintDB, CodeBlock ghidra_block, AddressSet addrSet, Program program) {

        m_listDB = listintDB;
        m_block = ghidra_block;
        m_addrSet = addrSet;

        m_dirtySMART = true; // Set it do dirty at the first time

        m_inpt = IRInterpreter.getInterpreter(program);

        /* Each basic block has its own SMARTable */
        m_smarTable = new SMARTable();
    }

    public CodeBlock getCodeBlock() {
        return m_block;
    }

    boolean isDirty() {
        return m_dirtySMART;
    }

    public Map<Long, Map<String, Set<String>>> getSMARTable() {
        return m_smarTable.m_tbl;
    }

    public void doRecording(MachineState state) {
        InstructionIterator iiter = m_listDB.getInstructions(m_addrSet, true); // for each instruction in this function
        SMARTable smart = new SMARTable();

        while (iiter.hasNext()) { // loop all instructions for this function
            Instruction inst = iiter.next();
            PcodeOp[] pcodes_list = inst.getPcode();
            for (PcodeOp currPcode : pcodes_list) { // loop all pcodes for this instruction
            	boolean suc = m_inpt.doRecording(state, smart, currPcode, inst);
            }
        }

        if (m_smarTable.containsAll(smart)) {
            m_dirtySMART = false;
        } else {
            m_smarTable.putAll(smart);
            m_dirtySMART = true;
        }
    }
}

class ExecutionBlock {
    private SMARBlock m_block;
    ExecutionBlock m_truecondBranch; // For conditional jumps, this node would be the jump target.
    ExecutionBlock m_falldownBranch;
    Set<ExecutionBlock> m_successor; // A set of successors

    private Set<MachineState> m_MachState;

    public boolean m_bVisted; // Visted in current cycle

    ExecutionBlock(Listing listintDB, Function function, CodeBlock ghidra_block, Program program) {
        AddressSet addrSet = ghidra_block.intersect(function.getBody());

        m_block = new SMARBlock(listintDB, ghidra_block, addrSet, program);
        m_MachState = new HashSet<>();
        m_bVisted = false;
    }

    public void setSuccessor(Set<ExecutionBlock> succsor) {
        m_successor = succsor;
    }

    public void setInitMachState(MachineState init_state) {
        if (m_MachState == null) {
            m_MachState = new HashSet<>();
        }

        m_MachState.add(init_state);
    }

    private void addMachState(MachineState new_state) {
        m_MachState.add(new_state);
    }

    public int getNumOfMachState() {
        if (m_MachState == null)
            return 0;
        else
            return m_MachState.size();
    }

    public CodeBlock getCodeBlock() {
        return m_block.getCodeBlock();
    }

    public boolean isSMRTDirty() {
        return m_block.isDirty();
    }

    public Map<Long, Map<String, Set<String>>> getSMARTable() {
        return m_block.getSMARTable();
    }

    public void runCFGOnce() {
        /*
         * Recording memory access at the start of the current code block, in DFS order
         */
        Set<MachineState> selfloopMachState = null; // A block may loop itself. If yes, we store a copy of MachineState
                                                    // for it

        m_bVisted = true; // Current block is already visted, so no need to traverse again at current
                          // cycle */

        /* Set the CPU state for each successor */
        for (Iterator<MachineState> itor = m_MachState.iterator(); itor.hasNext();) {
            MachineState mstate = itor.next();

            m_block.doRecording(mstate);

            /* Set the CPU state for each successor */
            int cntNxt = m_successor.size();
            for (ExecutionBlock nextBlk : m_successor) {
                cntNxt--;

                /* self-loop ? */
                if (nextBlk == this) {
                    /* If there is a self-loop, copy the CPU state for next traversing cycle */
                    if (selfloopMachState == null) {
                        selfloopMachState = new HashSet<>();
                    }
                    MachineState s = mstate.forkState();
                    selfloopMachState.add(s);
                    continue;
                }

                /* fork register status if there are more than 2 successors */
                if (cntNxt > 0) {
                    MachineState s = mstate.forkState();
                    nextBlk.addMachState(s);
                } else {
                    nextBlk.addMachState(mstate);
                }
            }

            /* use itor.remove() instead of Set.remove() */
            itor.remove();
        }

        /* All MachineState have been consumed */
        if (m_MachState.size() != 0) {
            throw new NullPointerException("Invalid machine state");
        }

        if (selfloopMachState != null) {
            m_MachState = selfloopMachState;
        }

        /* traverse all outgoing edges in this block */
        for (ExecutionBlock nextBlk : m_successor) {
            if (!nextBlk.m_bVisted && nextBlk.isSMRTDirty())
                nextBlk.runCFGOnce();
        }
    }

}

/*----------------------------copy from MachineState.java-------------------------------------------------------------------*/
/*
 * Machine state: A simple machine mode consist with only registers and memory
 */
class MachineState { // REGISTERS ARE IRRELAVANT IN PCODE SINCE IT IS PROCESSOR INDEPENDENT ??
    private Map<String, String> m_regs;
    private Map<String, String> m_mems;

    public MachineState(Map<String, String> register_status, Map<String, String> memory_status) {
        m_regs = register_status;
        m_mems = memory_status;
    }

    /* Used for forking */
    private MachineState() {

    }

    public static MachineState createInitState() {
        MachineState s = new MachineState();

        /* Set register values to symbolic initial values */
        s.m_regs = new HashMap<>(); // CPU State : Registers, will be added as they are seen since procecssor is unknown at the start
        s.m_mems = new HashMap<>(); // CPU State : Memory slot

        /*String[] allRegs = cpu.getAllRegisters(); PCODE DOES NOT HAVE FIXED REGISTERS, PROCESSOR DEPENDANT

        for (String reg : allRegs) {
            s.m_regs.put(reg, "V" + reg);
        }*/

        /* Doesn't need to initialize memory state */
        return s;
    }

    /* override me if needs */
    public void setRegValue(String register, String value) {
        m_regs.put(register, value);
    }

    /* override me if needs */
    public String getRegValue(String register) {
    	if (m_regs.get(register) == null) {
    		m_regs.put(register, "V" + register);
    	}
        return m_regs.get(register);
    }

    /* override me if needs */
    public void setMemValue(String address, String value) {
        m_mems.put(address, value);
    }

    /* override me if needs */
    public String getMemValue(String address) {
        return touchMemAddr(address);
    }

    /**
     * Make the memory address as never untouched
     *
     * @param address
     * @return
     */
    public String touchMemAddr(String address) {
        String value = m_mems.get(address);
        if (value == null) {
            String symbol;

            if (address.indexOf(' ') != -1) {
                symbol = String.format("V(%s)", address.replaceAll("\\s+", ""));
            } else {
                symbol = "V" + address;
            }

            m_mems.put(address, symbol);
            return symbol;
        } else {
            return value;
        }
    }

    /**
     * Make the memory address as never untouched
     *
     * @param address
     * @return
     */
    public void untouchMemAddr(String address) {
        m_mems.remove(address);
    }

    /**
     * Fork a Machine state to caller
     *
     * @param state
     * @param reuse
     */
    public MachineState forkState() {
        MachineState s = new MachineState();
        s.m_regs = _deepCopy(m_regs);
        s.m_mems = _deepCopy(m_mems);

        return s;
    }

    /**
     * Make a deep copy of a Map, for internal use only
     *
     * @param proto
     * @return
     */
    private Map<String, String> _deepCopy(Map<String, String> proto) {
        Map<String, String> to = new HashMap<>();

        for (Map.Entry<String, String> ent : proto.entrySet()) {
            String k = new String(ent.getKey());
            String v = new String(ent.getValue());
            to.put(k, v);
        }
        return to;
    }

    public String toString() {
        return String.format("%s %s", m_regs.toString(), m_mems.toString());
    }
}

/*----------------------------copy from SMARTable.java-------------------------------------------------------------------*/
/**
 * SMARTable, wrap a VSA table for each code-line. Can be used as Map
 */
class SMARTable {
    private static final String VINF = "VINF";
    private static int WIDENVS_THRESHOLD = 6; // tigger widening
    private SymbolicCalculator m_calc;

    public Map<Long, Map<String, Set<String>>> m_tbl;

    public SMARTable() {
        m_calc = SymbolicCalculator.getCalculator();
        m_tbl = new HashMap<>();
    }

    public int size() {
        return m_tbl.size();
    }

    public void clear() {
        m_tbl.clear();
    }

    /**
     * Put new mapVS into table. The same line of code may access other memory
     *
     * @param key
     * @param value
     */
    public void putDeep(Long key, Map<String, Set<String>> value) {
        /* The same line of code may access other memory */
        Map<String, Set<String>> mapVS = m_tbl.get(key);

        if (mapVS == null) {
            m_tbl.put(key, value);
        } else {
            mapVS.putAll(value);
        }
    }

    /* Interface for compatible with Map */
    public void put(Long key, Map<String, Set<String>> value) {
        putDeep(key, value);
    }

    /* Interface for compatible with Map */
    public Map<String, Set<String>> get(Long key) {
        return m_tbl.get(key);
    }

    /**
     * Use symbolic value VINF to widen value-set We do widening just for Equal
     * difference series
     *
     * @param final_set
     * @param new_set
     * @return
     */
    private boolean widenVS(Set<String> final_set, Set<String> new_set) {
        /* Already widened to VINF */
        if (final_set.contains("VINF"))
            return false;

        /* Union new_set before widening */
        final_set.addAll(new_set);

        /* do widening if it has more than WIDENVS_THRESHOLD values */
        if (final_set.size() < WIDENVS_THRESHOLD) {
            return false;
        } else {
            final_set.add(new String(VINF));
            return true;
        }
    }

    /**
     * Test if final_set contains all elements from new_set, considering windening
     *
     * @param final_set
     * @param new_set
     * @return
     */
    private boolean containVS(Set<String> final_set, Set<String> new_set) {
        if (final_set.containsAll(new_set)) {
            return true;
        } else if (final_set.contains("VINF")) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Test if containing-relationship between two SMAR-Tables
     *
     * @param new_smar_table
     * @return
     */
    public boolean containsAll(Map<Long, Map<String, Set<String>>> new_smar_table) {
        if (m_tbl.entrySet().containsAll(new_smar_table.entrySet())) {
            return true;
        }

        /* test if is widened? */
        boolean bContain;

        for (Map.Entry<Long, Map<String, Set<String>>> entNewSMARTbl : new_smar_table.entrySet()) {
            Long nNewLineno = entNewSMARTbl.getKey();
            Map<String, Set<String>> mapOldVSTble = m_tbl.get(nNewLineno);

            /* A new line of code is executed */
            if (mapOldVSTble == null)
                return false;

            /* Test if all values exist */
            Map<String, Set<String>> mapNewVSTble = entNewSMARTbl.getValue();
            for (Map.Entry<String, Set<String>> entNewVSTble : mapNewVSTble.entrySet()) {
                String strNewAddr = entNewVSTble.getKey();
                Set<String> setOldVS = mapOldVSTble.get(strNewAddr);

                /**
                 * The same line of code may may access another memory addrss, looping to access
                 * an array e.g. loop mov [rbp + rax], 0x10
                 */
                if (setOldVS == null)
                    continue;

                bContain = containVS(setOldVS, entNewVSTble.getValue());

                if (!bContain)
                    return false;
            }
        }
        return true;
    }

    /**
     * Test if containing-relationship between two SMAR-Tables
     *
     * @param new_smar_table
     * @return
     */
    public boolean containsAll(SMARTable new_smar_table) {
        return containsAll(new_smar_table.m_tbl);
    }

    /**
     * Put all values from new_smar_table into m_tbl
     *
     * @param new_smar_table
     */
    public void putAll(Map<Long, Map<String, Set<String>>> new_smar_table) {

        for (Map.Entry<Long, Map<String, Set<String>>> entNewSMARTbl : new_smar_table.entrySet()) {
            Long nNewLineno = entNewSMARTbl.getKey();
            Map<String, Set<String>> mapOldVSTble = m_tbl.get(nNewLineno);

            /* add all records from executing a new line of code */
            if (mapOldVSTble == null) {
                m_tbl.put(nNewLineno, entNewSMARTbl.getValue());
                continue;
            }

            /* Test if all values exist */
            Map<String, Set<String>> mapNewVSTble = entNewSMARTbl.getValue();
            for (Map.Entry<String, Set<String>> entNewVSTble : mapNewVSTble.entrySet()) {
                String strNewAddr = entNewVSTble.getKey();
                Set<String> setOldVS = mapOldVSTble.get(strNewAddr);

                if (setOldVS == null) {
                    mapOldVSTble.put(strNewAddr, entNewVSTble.getValue());
                } else {
                    widenVS(setOldVS, entNewVSTble.getValue());
                }
            }
        }
    }

    /**
     * Put all values from new_smar_table into m_tbl
     *
     * @param new_smar_table
     */
    public void putAll(SMARTable new_smar_table) {
        Map<Long, Map<String, Set<String>>> mapNewSMARTbl = new_smar_table.m_tbl;
        putAll(mapNewSMARTbl);
    }
}

/*----------------------------copy from VSAException.java-------------------------------------------------------------------*/
class VSAException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public String toString() {
        return "VSAException is triggered";
    }
}

/*----------------------------copy from X86Processor.java-------------------------------------------------------------------*/

class InvalidRegister extends VSAException {
    private String m_reg;

    public InvalidRegister(String register) {
        m_reg = register;
    }

    public String toString() {
        return String.format("Cannot find register -> %s", m_reg);
    }
}

class X86Processor {

    private static final String[] m_Regs64 = { "RAX", "RBX", "RCX", "RDX", "RDI", "RSI", "RBP", "RSP", "R8", "R9",
            "R10", "R11", "R12", "R13", "R14", "R15" };
    private static final String[] m_Regs32 = { "EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "EBP", "ESP", "R8D", "R9D",
            "R10D", "R11D", "R12D", "R13D", "R14D", "R15D" };
    private static final String[] m_Regs16 = { "AX", "BX", "CX", "DX", "DI", "SI", "BP", "SP", "R8W", "R9W", "R10W",
            "R11W", "R12W", "R13W", "R14W", "R15W" };
    private static final String[] m_Regs8h = { "AH", "BH", "CH", "DH" };
    private static final String[] m_Regs8l = { "AL", "BL", "CL", "DL", "DIL", "SIL", "BPL", "SPL", "R8B", "R9B", "R10B",
            "R11B", "R12B", "R13B", "R14B", "R15B" };
    private static final String[] m_RegSeg = { "FS", "GS" };
    private static final String[] m_RegXmm = { "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7", "XMM8",
            "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15" };

    private static Map<String, String> m_RegMap;
    private static String[] m_AllRegs;

    private static X86Processor m_singleton = null;

    private X86Processor() {
        createRegNameMapping();
        collectAllRegisters();
    }

    public static X86Processor getProcessor() {
        if (m_singleton == null) {
            m_singleton = new X86Processor();
        }
        return m_singleton;
    }

    /**
     * Create name mapping for register names
     */
    private void createRegNameMapping() {
        if (m_RegMap == null) {
            m_RegMap = new HashMap<>();
        }

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

    /**
     * Collect all available registers
     */
    private void collectAllRegisters() {
        if (m_AllRegs == null) {
            m_AllRegs = new String[m_RegSeg.length + m_RegXmm.length + m_Regs64.length];
        }

        String[] allRegs = m_AllRegs;
        System.arraycopy(m_RegSeg, 0, allRegs, 0, m_RegSeg.length);
        System.arraycopy(m_RegXmm, 0, allRegs, m_RegSeg.length, m_RegXmm.length);
        System.arraycopy(m_Regs64, 0, allRegs, m_RegSeg.length + m_RegXmm.length, m_Regs64.length);
        m_AllRegs = allRegs;
    }

    /* get the name of whole width register */
    public String getRegisterFullName(String register) {
        String Reg = m_RegMap.get(register);

        if (Reg == null) {
            throw new InvalidRegister(register);
        }
        return Reg;
    }

    /* Get all available registers on this architecture */
    public String[] getAllRegisters() {
        return m_AllRegs;
    }
}

/*----------------------------copy from X86Interpreter.java-------------------------------------------------------------------*/
class UnspportInstruction extends VSAException {
    private PcodeOp m_pcode;

    UnspportInstruction(PcodeOp pcode) {
        m_pcode = pcode;
    }

    public String toString() {
        String msg = String.format("Unsupported pcode -> %s", m_pcode.toString());
        return msg;
    }
}

// NOT UPATED FOR IR COMPATIBILITY YET
/*class InvalidOperand extends VSAException {
    private PcodeOp m_pcode;
    private Object[] m_objs;

    InvalidOperand(PcodeOp pcode, int operand_index) {
        m_pcode = pcode;
        m_objs = pcode.getInput(operand_index);
    }

    InvalidOperand(Object[] objs_of_MemOperand) {
        m_inst = null;
        m_objs = objs_of_MemOperand;
    }

    public String toString() {
        // print some details
        String[] msg = new String[m_objs.length + 1];

        for (int i = 0; i < m_objs.length; i++) {
            Object o = m_objs[i];

            if (o instanceof String)
                msg[i] = new String((String) o);
            else if (o instanceof Character)
                msg[i] = new String(Character.toString((Character) o));
            else
                msg[i] = new String(o.getClass().getName());
        }
        if (m_inst == null)
            msg[m_objs.length] = "";
        else
            msg[m_objs.length] = " @ " + m_inst.toString();

        return String.join(";", msg);
    }
}*/

class Interpreter {
    public boolean doRecording(Instruction inst) {
        System.out.println(inst.toString());
        return true;
    }
}

class IRInterpreter extends Interpreter {

    //private static X86Processor m_CPU; // x86-64 CPU
    //private static OperandType m_OPRDTYPE; // Use for testing opranad types
    private static SymbolicCalculator m_SymCalc; // Used for do symbolic calculation
    private static Program program;
    private static Language language;
    

    private Map<Long, Map<String, Set<String>>> m_SMART; // Memory access recording
    private MachineState m_MachState; // Machine state

    private static IRInterpreter m_singleton = null;

    private IRInterpreter(Program program) {
        m_SymCalc = SymbolicCalculator.getCalculator();
        this.program = program;
        this.language = program.getLanguage();
    }

    public static IRInterpreter getInterpreter(Program program) {
        if (m_singleton == null) {
            m_singleton = new IRInterpreter(program);
        }
        return m_singleton;
    }

    /*public X86Processor getCPU() {
        return m_CPU;
    }*/

    /**
     * Recording memroy accessing into @param table We deal with exceptions
     * including UnsupportedInstruction and InvalidOperand in this boundary
     *
     * @param state
     * @param table
     * @param inst
     * @return
     */
    public boolean doRecording(MachineState state, Map<Long, Map<String, Set<String>>> table, PcodeOp pcode, Instruction inst) {
        m_MachState = state;
        m_SMART = table;

        int nOprand = pcode.getNumInputs();

        try { // all pcode instructions only take 1 OR 2 inputs (execept CALL, CALLIND which are currently not handled)
            if (nOprand == 1) {
                _doRecording1(pcode,inst);
            } else if (nOprand == 2) {
                _doRecording2(pcode,inst);
            //} else if (nOprand == 3) {
            //    _doRecording3(inst);
            } else {
                /* Throw exception */
                throw new UnspportInstruction(pcode);
            }
            return true;

        } catch (UnspportInstruction e) {
            String fname = e.getStackTrace()[0].getFileName();
            int line = e.getStackTrace()[0].getLineNumber();

            System.err.println(String.format("%s:%d: %s", fname, line, e.toString()));
            return false;
        }
    }

    public boolean doRecording(MachineState state, SMARTable table, PcodeOp pcode, Instruction inst) {
        return doRecording(state, table.m_tbl, pcode, inst);
    }
    
    private void _doRecording1(PcodeOp pcode, Instruction inst) {
        // System.out.println("340: " + inst.toString());
        String op = pcode.getMnemonic();
        
        if (op.equalsIgnoreCase("COPY")) {return;}// do
        
        else if (op.equalsIgnoreCase("BRANCH")) {return;}// do
        	
        else if (op.equalsIgnoreCase("BRANCHIND")) {return;}
        	
        else if (op.equalsIgnoreCase("INT_ZEXT")) {return;} // do
        
        else if (op.equalsIgnoreCase("INT_SEXT")) {return;}
        
        else if (op.equalsIgnoreCase("INT_2COMP")) {return;}
        		
        else if (op.equalsIgnoreCase("INT_NEGATE")) {return;}// do
        			
        else if (op.equalsIgnoreCase("BOOL_NEGATE")) {return;}
        				
        else if (op.equalsIgnoreCase("FLOAT_NEG")) {return;}
        					
        else if (op.equalsIgnoreCase("FLOAT_ABS")) {return;}
        						
        else if (op.equalsIgnoreCase("FLOAT_SQRT")) {return;}
        							
        else if (op.equalsIgnoreCase("FLOAT_CEIL")) {return;}
        								
        else if (op.equalsIgnoreCase("FLOAT_FLOOR")) {return;}
        
        else if (op.equalsIgnoreCase("FLOAT_ROUND")) {return;}
        		
        else if (op.equalsIgnoreCase("FLOAT_NAN")) {return;}
        			
        else if (op.equalsIgnoreCase("INT2FLOAT")) {return;}
        				
        else if (op.equalsIgnoreCase("FLOAT2FLOAT")) {return;}
        					
        else if (op.equalsIgnoreCase("TRUNC")) {return;}

        else {
            throw new UnspportInstruction(pcode);
        }
        //return;
    }
    
    
    
    private void _doRecording2(PcodeOp pcode, Instruction inst) {
        String op = pcode.getMnemonic();
        
        // FOR TESTING
        if (op.equalsIgnoreCase("INT_ADD")) {_record2addsub(pcode,'+',inst);}
        else if (op.equalsIgnoreCase("INT_SUB")) {_record2addsub(pcode,'-',inst);}
        else if (op.equalsIgnoreCase("INT_MULT")) {_recordintmult(pcode,inst);}// do
        else if (op.equalsIgnoreCase("INT_LEFT")) {_recordbinaryshift(pcode,'u','l',inst);}
        else if (op.equalsIgnoreCase("INT_RIGHT")) {_recordbinaryshift(pcode,'u','r',inst);}// do
        else if (op.equalsIgnoreCase("INT_SRIGHT")) {_recordbinaryshift(pcode,'s','r',inst);}// do
        else if (op.equalsIgnoreCase("INT_XOR")) {_recordintbinaryop(pcode,'x',inst);}// do
        else if (op.equalsIgnoreCase("INT_AND")) {_recordintbinaryop(pcode,'n',inst);}// do
        else if (op.equalsIgnoreCase("INT_OR")) {_recordintbinaryop(pcode,'o',inst);}// do
        /*
        else if (op.equalsIgnoreCase("STORE")) {_recordstore(pcode,inst);}// do
        else if (op.equalsIgnoreCase("LOAD")) {return;} // do
        else if (op.equalsIgnoreCase("PIECE")) {_recordpiece(pcode,inst);}
        else if (op.equalsIgnoreCase("SUBPIECE")) {_recordsubpiece(pcode,inst);}
        else if (op.equalsIgnoreCase("INT_EQUAL")) {_recordintequal(pcode,inst);}// do
        else if (op.equalsIgnoreCase("INT_NOTEQUAL")) {_recordintnotequal(pcode,inst);}// do
        else if (op.equalsIgnoreCase("INT_LESS")) {_recordintless(pcode,'u',inst);}// do
        else if (op.equalsIgnoreCase("INT_SLESS")) {_recordintless(pcode,'s',inst);} // do
        else if (op.equalsIgnoreCase("INT_LESSEQUAL")) {_recordintlessequal(pcode,'u',inst);}
        else if (op.equalsIgnoreCase("INT_SLESSEQUAL")) {_recordintlessequak(pcode,'s',inst);}
        else if (op.equalsIgnoreCase("INT_CARRY")) {_recordcarry(pcode,'u',inst);}// do
        else if (op.equalsIgnoreCase("INT_SCARRY")) {_recordcarry(pcode,'s',inst);}// do
        else if (op.equalsIgnoreCase("INT_SBORROW")) {_recordsborrow(pcode,inst);}// do
        else if (op.equalsIgnoreCase("INT_DIV")) {_recordintdiv(pcode,'u',inst);}
        else if (op.equalsIgnoreCase("INT_REM")) {_recordintrem(pcode,'u',inst);}
        else if (op.equalsIgnoreCase("INT_SDIV")) {_recordintdiv(pcode,'s',inst);}
        else if (op.equalsIgnoreCase("INT_SREM")) {_recordintrem(pcode,'s',inst);}
        else if (op.equalsIgnoreCase("BOOL_XOR")) {_recordbolbinaryop(pcode,'x',inst);}
        else if (op.equalsIgnoreCase("BOOL_AND")) {_recordbolbinaryop(pcode,'n',inst);}
        else if (op.equalsIgnoreCase("BOOL_OR")) {_recordbolbinaryop(pcode,'o',inst);}// do
        else if (op.equalsIgnoreCase("FLOAT_EQUAL")) {_recordfloatinequality(pcode,'=',inst);}
        else if (op.equalsIgnoreCase("FLOAT_NOTEQUAL")) {_recordfloatinequality(pcode,'!=',inst);}
        else if (op.equalsIgnoreCase("FLOAT_LESS")) {_recordfloatinequality(pcode,'<',inst);}
        else if (op.equalsIgnoreCase("FLOAT_LESSEQUAL")) {_recordfloatinequality(pcode,'<=',inst);}
        else if (op.equalsIgnoreCase("FLOAT_ADD")) {_recordfloatarith(pcode,'+',inst);}
        else if (op.equalsIgnoreCase("FLOAT_SUB")) {_recordfloatarith(pcode,'-',inst);}
        else if (op.equalsIgnoreCase("FLOAT_MULT")) {_recordfloatarith(pcode,'*',inst);}
        else if (op.equalsIgnoreCase("FLOAT_DIV")) {_recordfloatarith(pcode,'/',inst);}
        else if (op.equalsIgnoreCase("RETURN")) {} // not implemented
        else {throw new UnspportInstruction(pcode);}
        */
        return;
    }
    
    
    private void _record2addsub(PcodeOp pcode, char op, Instruction inst) {
    	Varnode varnode0 = pcode.getInput(0);
		Varnode varnode1 = pcode.getInput(1);
		String strVal0, strVal1, strRes;
		Varnode resVarnode = pcode.getOutput();
		
    	if (varnode0.isConstant()) { // first input is constant 
    		strVal0 = varnode2longstring(varnode0);
    		
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant
    			
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}
    	
    	else if (varnode0.isRegister()) { // first input is register 
    		strVal0 = getMemoryValue(varnode0.toString(language));
    		
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant
    			
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}
    	else { // first input is var
    		strVal0 = getMemoryValue(getStringAddr(varnode0));
    		
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant
    			
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}

        if (op == '+') { strRes = m_SymCalc.symbolicAdd(strVal0, strVal1); }
        else { strRes = m_SymCalc.symbolicSub(strVal0, strVal1); }

        
        updateMemoryWriteAccess(inst.getAddress(), getStringAddr(resVarnode), strRes);
    }
    
    //input0 	(special) 	Constant ID of space to store into.
    //input1 		Varnode containing pointer offset of destination.
    //input2 		Varnode containing data to be stored.
    /*private void _recordstore(PcodeOp pcode,Instruction inst) {
    	Varnode varnode1 = pcode.getInput(1);
		Varnode varnode2 = pcode.getInput(2);
		String strVal1, strVal2, strRes;
		Varnode resVarnode = pcode.getOutput();
		
    	if (varnode0.isConstant()) { // first input is constant 
    		strVal0 = varnode2longstring(varnode0);
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}
    	else 
    		printf("Error!");
    	
    	strRes = m_SymCalc.symbolicMul(strVal0, strVal1);
        updateMemoryWriteAccess(inst.getAddress(), getStringAddr(resVarnode), strRes);
    }
    
    // 1st input: address space ; 2nd input: offset of source from address space
    private void _recordload(PcodeOp pcode, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;
        Address res = pcode.getOutput().getAddress();

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            // "special" input?
            
            updateMemoryWriteAccess(inst.getAddress(), res.toString(), strRes);
    }
    // input0: target address space's constant ID, input1: target's offset into addr space, input2: data to be stored
    // how to exract dst address space and offset?
    private void _recordstore(PcodeOp pcode, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        Varnode varnode2 = pcode.getInput(2);
        String strVal0, strVal1, strVal2, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            String strAddr2 = _calcMemAddress(varnode2);
            // OPERATION TO-DO
            // "special" input?
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr2, strRes);
    }
    
    private void _recordpiece(PcodeOp pcode, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
    private void _recordsubpiece(PcodeOp pcode, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
    private void _recordintequal(PcodeOp pcode, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
    private void _recordintnotequal(PcodeOp pcode, char op, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
    // 'format' identifies inputs as signed or unsigned
    private void _recordintless(PcodeOp pcode, char format, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
 // 'format' identifies inputs as signed or unsigned
    private void _recordintlessequal(PcodeOp pcode, char format, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
    // 'format' identifies inputs as signed or unsigned
    private void _recordintcarry(PcodeOp pcode, char format, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
    private void _recordsborrow(PcodeOp pcode, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
        */
    // 'x' - XOR ; 'n' - AND ; 'o' - OR
    private void _recordintbinaryop(PcodeOp pcode, char op, Instruction inst) {
    	Varnode varnode0 = pcode.getInput(0);
		Varnode varnode1 = pcode.getInput(1);
		String strRes;
		Varnode resVarnode = pcode.getOutput();
		BigInteger res;
		BigInteger value0 = new BigInteger(Long.decode(varnode0.toString(language)).toString());
		BigInteger value1 = new BigInteger(Long.decode(varnode1.toString(language)).toString());
		
		if(op == 'x') {res = value0.xor(value1);}
		else if (op == 'n') {res = value0.and(value1);}
		else {res = value0.or(value1);}
		
		strRes = res.toString(10);
		
        updateMemoryWriteAccess(inst.getAddress(), getStringAddr(resVarnode), strRes);
    }

    // dir: 'r' - right ; 'l' - left; input0 is the varnode being shift, input1 is the shift amount
    private void _recordbinaryshift(PcodeOp pcode, char format, char dir, Instruction inst) {
    	Varnode varnode0 = pcode.getInput(0);
		Varnode varnode1 = pcode.getInput(1);
		String strVal0, strVal1, strRes;
		Varnode resVarnode = pcode.getOutput();
		
    	if (varnode0.isConstant()) { // first input is constant 
    		strVal0 = varnode2longstring(varnode0);
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}
    	else if (varnode0.isRegister()) { // first input is register 
    		strVal0 = getMemoryValue(varnode0.toString(language));
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}
    	else { // first input is var
    		strVal0 = getMemoryValue(getStringAddr(varnode0));
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant	
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}
    	
    	if (format == 's') { // format value of first input if its a signed value
    		if (strVal0.endsWith("0")) {
    			String neg = "-";
    			strVal0 = neg.concat(strVal0);
    		}
    		strVal0 = strVal0.substring(0,strVal0.length()-2);
    	}

    	if (dir == 'l') { strRes = m_SymCalc.symbolicMul(strVal0, Long.decode(strVal1) * 2); }
    	else { strRes = m_SymCalc.symbolicDiv(strVal0, Long.decode(strVal1) * 2); }
        
        updateMemoryWriteAccess(inst.getAddress(), getStringAddr(resVarnode), strRes);
    }
    
    private void _recordintmult(PcodeOp pcode, Instruction inst) {
    	Varnode varnode0 = pcode.getInput(0);
		Varnode varnode1 = pcode.getInput(1);
		String strVal0, strVal1, strRes;
		Varnode resVarnode = pcode.getOutput();
		
    	if (varnode0.isConstant()) { // first input is constant 
    		strVal0 = varnode2longstring(varnode0);
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant	
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}
    	else if (varnode0.isRegister()) { // first input is register 
    		strVal0 = getMemoryValue(varnode0.toString(language));
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant	
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}
    	else { // first input is var
    		strVal0 = getMemoryValue(getStringAddr(varnode0));
    		if (varnode1.isConstant()) { strVal1 = varnode2longstring(varnode1); } // second input is constant	
    		else if (varnode1.isRegister()) { strVal1 = getMemoryValue(varnode1.toString(language)); } // second input is register
    		else { strVal1 = getMemoryValue(getStringAddr(varnode1)); } // second input is a variable
    	}

        strRes = m_SymCalc.symbolicMul(strVal0, strVal1);
        updateMemoryWriteAccess(inst.getAddress(), getStringAddr(resVarnode), strRes);
    }
    /*
    private void _recordintdiv(PcodeOp pcode, char format, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            strRes = m_SymCalc.symbolicMul(strVal0, strVal1);
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
    private void _recordintrem(PcodeOp pcode, char format, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
 // 'x' - XOR ; 'n' - AND ; 'o' - OR
    private void _recordbolbinaryop(PcodeOp pcode, char op, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
    private void _recordfloatinequality(PcodeOp pcode, char inequality, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }
    
    private void _recordfloatarith(PcodeOp pcode, char op, Instruction inst) {
        Varnode varnode0 = pcode.getInput(0);
        Varnode varnode1 = pcode.getInput(1);
        String strVal0, strVal1, strRes;

            String strAddr0 = _calcMemAddress(varnode0);
            strVal0 = getMemoryValue(strAddr0);
            
            String strAddr1 = _calcMemAddress(varnode1);
            strVal1 = getMemoryValue(strAddr1);
            
            // OPERATION TO-DO
            
            updateMemoryWriteAccess(inst.getAddress(), strAddr0, strRes);
    }*/

    private String _calcMemAddress(Varnode varnode) { //VAR UNIQUELY IDENTIFIED BY OFFSET ONLY?
        return String.valueOf(varnode.getOffset());
    }

    // override me if needs
    private String getMemoryValue(String address) {
        return m_MachState.getMemValue(address);
    }

    private boolean updateRegisterWriteAccess(long inst_address, String reg, String value) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;

        // Update SMAR-table for Register reg
        tmpMap = m_SMART.get(inst_address);
        if (tmpMap == null) {
            tmpMap = new HashMap<>();
            m_SMART.put(inst_address, tmpMap);
        }

        //reg = m_CPU.getRegisterFullName(reg);
        tmpSet = tmpMap.get(reg);
        if (tmpSet == null) {
            tmpSet = new HashSet<>();
            tmpMap.put(reg, tmpSet);
        }

        // assert (tmpSet != null);
        tmpSet.add(value);

        // for debugging 
        // System.out.println(String.format("674: @0x%x: %s = %s", inst_address, reg,
        // value));

        // Update register state
        m_MachState.setRegValue(reg, value);

        return true;
    }

    private boolean updateRegisterWriteAccess(Address instruction_address, Register reg, String value) {
        return updateRegisterWriteAccess(instruction_address.getOffset(), reg.getName(), value);
    }

    private boolean updateRegisterWriteAccess(Address instruction_address, String reg, String value) {
        return updateRegisterWriteAccess(instruction_address.getOffset(), reg, value);
    }

    private boolean updateMemoryWriteAccess(long inst_address, String address, String value) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;

        // Update MAR-table for address
        tmpMap = m_SMART.get(inst_address);
        if (tmpMap == null) {
            tmpMap = new HashMap<>();
            m_SMART.put(inst_address, tmpMap);
        }

        tmpSet = tmpMap.get(address);
        if (tmpSet == null) {
            tmpSet = new HashSet<>();
            tmpMap.put(address, tmpSet);
        }

        // assert (tmpSet != null);
        tmpSet.add(value);

        // for debuging
        // System.out.println(String.format("686: @0x%x: [%s] = %s", inst_address,
        // address, value));

        // Update memory status
        m_MachState.setMemValue(address, value);

        return true;
    }

    private boolean updateMemoryWriteAccess(Address inst_address, String memory_address, String value) {
        return updateMemoryWriteAccess(inst_address.getOffset(), memory_address, value);
    }

    private boolean updateMemoryReadAccess(long inst_address, String address) {
        Map<String, Set<String>> tmpMap;
        Set<String> tmpSet;
        String value;

        value = m_MachState.getMemValue(address);

        // Update MAR-table for memory read
        tmpMap = m_SMART.get(inst_address);
        if (tmpMap == null) {
            tmpMap = new HashMap<>();
            m_SMART.put(inst_address, tmpMap);
        }

        tmpSet = tmpMap.get(address);
        if (tmpSet == null) {
            tmpSet = new HashSet<>();
            tmpMap.put(address, tmpSet);

            tmpSet.add(value); // Set a symbolic value
        }

        return true;
    }

    private boolean updateMemoryReadAccess(Address inst_address, String memory_address) {
        return updateMemoryReadAccess(inst_address.getOffset(), memory_address);
    }
    
    private String varnode2longstring (Varnode varnode) {
    	long temp = Long.decode(varnode.toString(language));
    	return Long.toString(temp);
    }
    
    private String getStringAddr(Varnode varnode) {
    	return String.valueOf(varnode.getAddress().hashCode());
    }
}

/*----------------------------copy from SymbolicCalculator.java-------------------------------------------------------------------*/
class InvalidSymboicValue extends VSAException {
    private String m_symbol;

    public InvalidSymboicValue(String symbol) {
        m_symbol = symbol;
    }

    public String toString() {
        return String.format("InvalidSymboicValue -> %s", m_symbol);
    }
}

class InvalidSymboicOperation extends VSAException {
    private String m_msg;

    public InvalidSymboicOperation(String expression) {
        m_msg = expression;
    }

    public String toString() {
        return String.format("InvalidSymboicOperation -> %s", m_msg);
    }
}

/**
 * Encapsulate calculatoin for symbolic values Singleton mode
 */
class SymbolicCalculator {

    private static SymbolicCalculator m_calc = null; // Singleton mode

    final DecimalFormat m_digitFmt; // Add a +/- sign before digit values

    private SymbolicCalculator() {
        m_digitFmt = new DecimalFormat("+#;-#");
    }

    public static SymbolicCalculator getCalculator() {
        if (m_calc == null) {
            m_calc = new SymbolicCalculator();
        }
        return m_calc;
    }

    public String symbolicAdd(String symbol0, String symbol1) {
        return symbolicBinaryOP(symbol0, '+', symbol1);
    }

    public String symbolicSub(String symbol0, String symbol1) {
        return symbolicBinaryOP(symbol0, '-', symbol1);
    }

    public String symbolicMul(String symbol0, String symbol1) {
        return symbolicBinaryOP(symbol0, '*', symbol1);
    }

    public String symbolicDiv(String symbol0, String symbol1) {
        return symbolicBinaryOP(symbol0, '/', symbol1);
    }

    public String symbolicXor(String symbol0, String symbol1) {
        return symbolicBinaryOP(symbol0, '^', symbol1);
    }

    /**
     * Binary operations for two symbolic values.
     *
     * @param symbol0
     * @param op
     * @param symbol1
     * @return
     */
    public String symbolicBinaryOP(String symbol0, char op, String symbol1) {
        String[] elems0 = symbol0.split("\\s", 0);
        String[] elems1 = symbol1.split("\\s", 0);

        /* parse the symbolic value symbol0 */
        String part0S; // Symbolic part in symbol0
        long part0V; // Value part in symbol0

        if (elems0.length == 1) {
            if (isPureDigital(elems0[0])) {
                part0S = "0";
                part0V = Long.decode(elems0[0]);
            } else if (isPureSymbolic(elems0[0])) {
                part0S = elems0[0];
                part0V = 0;
            } else {
                throw new InvalidSymboicValue(symbol0);
            }
        } else if (elems0.length == 2) {
            part0S = elems0[0];
            part0V = Long.decode(elems0[1]);
        } else {
            /* We assume each value has at most two parts. */
            throw new InvalidSymboicValue(symbol0);
        }

        /* parse the symbolic value symbol1 */
        String part1S; // Symbolic part in symbol0
        long part1V; // Value part in symbol0

        if (elems1.length == 1) {
            if (isPureDigital(elems1[0])) {
                part1S = "0";
                part1V = Long.decode(elems1[0]);
            } else if (isPureSymbolic(elems1[0])) {
                part1S = elems1[0];
                part1V = 0;
            } else {
                throw new InvalidSymboicValue(symbol1);
            }
        } else if (elems1.length == 2) {
            part1S = elems1[0];
            part1V = Long.decode(elems1[1]);
        } else {
            /* We assume each value has at most two parts. */
            throw new InvalidSymboicValue(symbol1);
        }

        /* calculate the result */
        String tmpS, newSymbol;
        long tmpV;

        if (op == '+' || op == '-') {
            tmpS = binaryOP(part0S, op, part1S);
            tmpV = binaryOP(part0V, op, part1V);
            newSymbol = binaryOP(tmpS, '+', tmpV);

        } else if (op == '*') {
            if (part0S.equals("0") || part1S.equals("0")) {
                if (part0S.equals("0")) {
                    tmpS = binaryOP(part1S, '*', part0V);
                } else {
                    tmpS = binaryOP(part0S, '*', part1V);
                }

                tmpV = binaryOP(part0V, '*', part1V);
                newSymbol = binaryOP(tmpS, '+', tmpV);

            } else {
                String tmpL, tmpR;

                tmpS = binaryOP(part0S, '*', part1S);
                tmpL = binaryOP(part0S, '*', part1V);
                tmpR = binaryOP(part1S, '*', part0V);
                tmpV = binaryOP(part0V, '*', part1V);

                newSymbol = binaryOP(tmpS, '+', tmpL);
                newSymbol = binaryOP(newSymbol, '+', tmpR);
                newSymbol = binaryOP(newSymbol, '+', tmpV);
            }

        } else if (op == '/') {
            if (symbol0.equals(symbol1)) {
                newSymbol = "1";

            } else if (part0S.equals("0") && part0V == 0) {
                newSymbol = "0";

            } else if (part0S.equals("0") && part1S.equals("0")) {
                tmpV = binaryOP(part0V, '/', part1V);
                newSymbol = binaryOP("0", '+', tmpV);

            } else if (!part0S.equals("0") && part1S.equals("0")) {
                /* (VRSP + 100)/10 or VRSP/10 */
                if (part0V == 0) {
                    newSymbol = String.format("D(%s/%d)", part0S, part1V);
                } else {
                    if (part0V % part1V == 0) {
                        newSymbol = String.format("D(%s/%d) %s", part0S, part1V, m_digitFmt.format(part0V / part1V));
                    } else {
                        newSymbol = String.format("D(%s%s/%d)", part0S, m_digitFmt.format(part0V), part1V);
                    }
                }
            } else if (part0S.equals("0") && !part1S.equals("0")) {
                if (part1V == 0) {
                    newSymbol = String.format("D(%d/%s)", part0V, part1S);
                } else {
                    newSymbol = String.format("D(%d/%s%s)", part0V, part1S, m_digitFmt.format(part1V));
                }

            } else {
                part0S = symbol0.replaceAll("\\s", "");
                part1S = symbol1.replaceAll("\\s", "");
                newSymbol = String.format("D(%s/%s)", part0S, part1S);
            }

        } else if (op == '^') {
            if (symbol0.equals(symbol1)) {
                newSymbol = "0";
            } else {
                part0S = symbol0.replaceAll("\\s", "");
                part1S = symbol1.replaceAll("\\s", "");
                newSymbol = String.format("D(%s^%s)", part0S, part1S);
            }
        } else {
            /* Thow exception */
            String msg = String.format("(%s) %s (%s)", symbol0, Character.toString(op), symbol1);
            throw new InvalidSymboicOperation(msg);
        }

        return newSymbol;
    }

    public String symbolicAdd(String symbol, long value) {
        return symbolicBinaryOP(symbol, '+', value);
    }

    public String symbolicSub(String symbol, long value) {
        return symbolicBinaryOP(symbol, '-', value);
    }

    public String symbolicMul(String symbol, long value) {
        return symbolicBinaryOP(symbol, '*', value);
    }

    public String symbolicDiv(String symbol, long value) {
        return symbolicBinaryOP(symbol, '/', value);
    }

    /**
     * Binary operation for a symbolic-value and an integer value
     *
     * @param symbol
     * @param op
     * @param value
     * @return A symbolic-value
     */
    public String symbolicBinaryOP(String symbol, char op, long value) {
        String[] elems = symbol.split("\\s", 0);

        /* parse the symbolic value */
        String partS; // symbolic part of symbol
        long partV; // Numeric part of symbol

        if (elems.length == 1) {
            if (isPureDigital(elems[0])) {
                partS = "";
                partV = Long.decode(elems[0]);
            } else if (isPureSymbolic(elems[0])) {
                partS = elems[0];
                partV = 0;
            } else {
                throw new InvalidSymboicValue(symbol);
            }

        } else if (elems.length == 2) {
            partS = elems[0];
            partV = Long.decode(elems[1]);

        } else {
            /* We assume the symbolic value has at most two parts */
            throw new InvalidSymboicValue(symbol);
        }

        String newSymbol;
        long newValue;

        if (partS.equals("")) {
            newValue = binaryOP(partV, op, value);
            newSymbol = binaryOP("0", '+', newValue);

        } else if (partV == 0) {
            newSymbol = binaryOP(partS, op, value);

        } else {
            if (op == '+' || op == '-') {
                newValue = binaryOP(partV, op, value);
                newSymbol = binaryOP(partS, '+', newValue);

            } else if (op == '*') {
                newValue = binaryOP(partV, op, value);
                newSymbol = binaryOP(partS, op, value);
                newSymbol = binaryOP(newSymbol, '+', newValue);

            } else if (op == '/') {
                if (partV % value == 0) {
                    newValue = binaryOP(partV, op, value);
                    newSymbol = binaryOP(partS, op, value);
                    newSymbol = binaryOP(newSymbol, '+', newValue);
                } else {
                    newSymbol = String.format("D(%s%s/%d)", partS, m_digitFmt.format(partV), value);
                }

            } else if (op == '^') {
                newSymbol = String.format("D(%s%s^%d)", partS, m_digitFmt.format(partV), value);

            } else {
                String msg = String.format("(%s) %s %d", symbol, Character.toString(op), value);
                throw new InvalidSymboicOperation(msg);
            }
        }

        return newSymbol;
    }

    /**
     * Binary operation for two pure-symbolic values
     *
     * @param pure_symbol0
     * @param op
     * @param pure_symbol1
     * @return
     */
    private String binaryOP(String pure_symbol0, char op, String pure_symbol1) {
        if (!isPureSymbolic(pure_symbol0) || !isPureSymbolic(pure_symbol1)) {
            throw new InvalidSymboicValue(pure_symbol0 + " or " + pure_symbol1);
        }

        String newSymbol;
        long newValue;

        if (isZero(pure_symbol0))
            pure_symbol0 = "";
        if (isZero(pure_symbol1))
            pure_symbol1 = "";

        if (op == '+') {
            if (pure_symbol0.equals("") || pure_symbol1.equals("")) {
                newSymbol = pure_symbol0 + pure_symbol1;
                if (newSymbol.equals(""))
                    newSymbol = "0";

            } else if (pure_symbol0.equals("-" + pure_symbol1) || pure_symbol1.equals("-" + pure_symbol0)) {
                newSymbol = "0";
            } else {
                /* Cannot parse */
                newSymbol = String.format("D(%s+%s)", pure_symbol0, pure_symbol1);
            }

        } else if (op == '-') {
            if (pure_symbol0.equals(pure_symbol1)) {
                newSymbol = "0";
            } else if (pure_symbol0.equals("")) {
                newSymbol = String.format("-%s", pure_symbol1);
            } else if (pure_symbol1.equals("")) {
                newSymbol = pure_symbol0;
            } else {
                /* Cannot parse */
                newSymbol = String.format("D(%s-%s)", pure_symbol0, pure_symbol1);
            }

        } else if (op == '*') {
            if (pure_symbol0.equals("") || pure_symbol1.equals("")) {
                newSymbol = "0";
            } else {
                newSymbol = String.format("D(%s*%s)", pure_symbol0, pure_symbol1);
            }

        } else if (op == '/') {
            if (pure_symbol0.equals(pure_symbol1)) {
                newSymbol = "1";
            } else if (pure_symbol0.equals("")) {
                newSymbol = "0";
            } else if (pure_symbol1.equals("")) {
                String msg = String.format("(%s) %s (%s)", pure_symbol0, Character.toString(op), pure_symbol1);
                throw new InvalidSymboicOperation(msg);
            } else {
                newSymbol = String.format("D(%s/%s)", pure_symbol0, pure_symbol1);
            }

        } else if (op == '^') {
            if (pure_symbol0.equals(pure_symbol1)) {
                newSymbol = "0";
            } else {
                newSymbol = String.format("D(%s^%s)", pure_symbol0, pure_symbol1);
            }

        } else {
            String msg = String.format("(%s) %s (%s)", pure_symbol0, Character.toString(op), pure_symbol0);
            throw new InvalidSymboicOperation(msg);
        }

        return newSymbol;
    }

    /**
     * Binary operation for a pure-symbolic value and an integer value e.g. VRSP +
     * 0x8; VRSP - 0x8; VRSP * 0x8; VRSP / 0x8;
     *
     * @param pure_symbol
     * @param op
     * @param value
     * @return a symbolic value
     */
    private String binaryOP(String pure_symbol, char op, long value) {
        if (!isPureSymbolic(pure_symbol)) {
            throw new InvalidSymboicValue(pure_symbol);
        }

        String newSymbol;
        long newValue;

        if (isZero(pure_symbol))
            pure_symbol = "";

        if (pure_symbol.equals("")) {
            if (op == '+') {
                newValue = value;
            } else if (op == '-') {
                newValue = 0 - value;
            } else if (op == '*') {
                newValue = 0;
            } else if (op == '/') {
                newValue = 0;
            } else {
                String msg = String.format("(%s) %s %d", pure_symbol, Character.toString(op), value);
                throw new InvalidSymboicOperation(msg);
            }
            newSymbol = String.format("%d", newValue);

        } else if (value == 0) {
            if (op == '+') {
                newSymbol = pure_symbol;
            } else if (op == '-') {
                newSymbol = pure_symbol;
            } else if (op == '*') {
                newSymbol = "0";
            } else {
                String msg = String.format("(%s) %s %d", pure_symbol, Character.toString(op), value);
                throw new InvalidSymboicOperation(msg);
            }

        } else {
            if (op == '+') {
                newValue = value;
                newSymbol = String.format("%s %s", pure_symbol, m_digitFmt.format(newValue));
            } else if (op == '-') {
                newValue = 0 - value;
                newSymbol = String.format("%s %s", pure_symbol, m_digitFmt.format(newValue));
            } else if (op == '*') {
                newValue = value;

                if (value == 1) {
                    newSymbol = pure_symbol;
                } else {
                    newSymbol = String.format("D(%s*%d)", pure_symbol, newValue);
                }
            } else if (op == '/') {
                newValue = value;

                if (value == 1) {
                    newSymbol = pure_symbol;
                } else {
                    newSymbol = String.format("D(%s/%s)", pure_symbol, newValue);
                }
            } else if (op == '^') {
                newValue = value;
                newSymbol = String.format("D(%s^%s)", pure_symbol, newValue);
            } else {
                String msg = String.format("(%s) %s %d", pure_symbol, Character.toString(op), value);
                throw new InvalidSymboicValue(msg);
            }
        }

        return newSymbol;
    }

    /**
     * Binary operation for two long values: 0x12 + 0x34; 0x12 - 0x34; 0x12 * 0x34;
     * 0x12 / 0x34; 0x12 ^ 0x34
     *
     * @param value0
     * @param op
     * @param value1
     * @return
     */
    public long binaryOP(long value0, char op, long value1) {
        long res;

        if (op == '+') {
            res = value0 + value1;
        } else if (op == '-') {
            res = value0 - value1;
        } else if (op == '*') {
            res = value0 * value1;
        } else if (op == '/') {
            res = value0 / value1;
        } else if (op == '^') {
            res = value0 ^ value1;
        } else {
            throw new InvalidSymboicOperation(Character.toString(op));
        }
        return res;
    }

    public long symbolicBinaryOP(long value0, char op, long value1) {
        return binaryOP(value0, op, value1);
    }

    /**
     * Test if it is symbolic value: which is defined as: 1. starting with
     * (-)[V|D]xxx or 2. a digital value, 3. may contain spaces
     *
     * @param symbol
     * @return
     */
    public boolean isSymbolicValue(String symbol) {
        String[] parts = symbol.split("\\s", 0);

        for (String e : parts) {
            if (!(isPureSymbolic(e) || isPureDigital(e))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Test if it is a pure symbolic value, which is defined as: 1. [V|D]xxx 2.
     * ditigal 0; 3. no space, 4. sign-extended
     *
     * @param symbol
     * @return
     */
    public boolean isPureSymbolic(String symbol) {
        boolean yes;
        int len = symbol.length();

        if (symbol.length() < 1 || symbol.contains(" ")) {
            /* should no spaces */
            yes = false;
        } else if (isZero(symbol)) {
            yes = true;
        } else if ((symbol.charAt(0) == 'V') || (symbol.charAt(0) == 'D')) {
            yes = (symbol.length() > 1);
        } else if (symbol.charAt(0) == '-' && ((symbol.charAt(0) == 'V') || (symbol.charAt(0) == 'D'))) {
            /* sign extend */
            yes = (symbol.length() > 2);
        } else {
            yes = false;
        }

        return yes;
    }

    /**
     * Test if the symbol is zero or not
     *
     * @param symbol
     * @return
     */
    public boolean isZero(String symbol) {
        if (isPureDigital(symbol)) {
            long n = Long.decode(symbol);
            return (n == 0);
        }
        return false;
    }

    /**
     * Test if a symbolic value is pure digitvalue
     *
     * @param symbol
     * @return
     */
    public boolean isPureDigital(String symbol) {
        boolean yes = false;
        try {
            Long.decode(symbol);
            yes = true;
        } catch (Exception e) {

        }
        return yes;
    }
}

/*----------------------------copy from DataAccessAnalysis.java-------------------------------------------------------------------*/
class DataAccessAnalysis {
    private SymbolicCalculator m_calc;

    private Set<Map<String, List<Long>>> m_setArrayAccess;
    private Map<String, List<Long>> m_mapStructAccess;

    public DataAccessAnalysis(Map<Long, Map<String, Set<String>>> symbolic_memory_access_table) {
        m_calc = SymbolicCalculator.getCalculator();

        m_setArrayAccess = new HashSet<>();
        m_mapStructAccess = new HashMap<>();

        inferMemScopes(symbolic_memory_access_table);

        /* sort all data in asending order */
        for (Map<String, List<Long>> mapAccess : m_setArrayAccess) {
            for (Map.Entry<String, List<Long>> entMapAccess : mapAccess.entrySet()) {
                Collections.sort(entMapAccess.getValue());
            }
        }

        /* sorting all data in asending order */
        for (Map.Entry<String, List<Long>> entMapScope : m_mapStructAccess.entrySet()) {
            Collections.sort(entMapScope.getValue());
        }
    }

    /**
     * In a function, there maybe more than 1 arrays within the same scope. e.g. tow
     * differrence arrays on local stack
     *
     * @param array_access
     * @param value_sets
     */
    private boolean _findPossibleArrayAccess(Map<String, Set<String>> value_sets) {
        /*
         * Get a list of accessed memory address by this line of code. Just considering
         * symbolic address. e.g. [RAX, VRSP -1228, VRSP -1216, VRSP -1224]
         */
        List<Long> listVS;
        String scope;

        List<String> listAddr = new ArrayList<>();
        for (String addr : value_sets.keySet()) {
            if (addr.length() < 1 || addr.charAt(0) != 'V')
                continue;
            listAddr.add(addr);
        }
        if (listAddr.size() < 4)
            return false;

        /* Get the scope name */
        scope = listAddr.get(0).split(" ", 0)[0];

        /* Al memory addresses are in the same scope ? */
        boolean bSameScope = true;
        String delta;

        listVS = new ArrayList<>();
        for (int i = 0; i < listAddr.size(); i++) {
            delta = m_calc.symbolicSub(listAddr.get(i), scope);
            if (!m_calc.isPureDigital(delta)) {
                bSameScope = false;
                break;
            } else {
                Long v = Long.decode(delta);
                if (listVS.contains(v))
                    continue;
                listVS.add(v);
            }
        }

        if (!bSameScope)
            return false;

        /* Sort values in asending order */
        Collections.sort(listVS);

        /* Now, we get an array accessing pattern */
        Map<String, List<Long>> newarray = new HashMap<>();
        newarray.put(scope, listVS);
        m_setArrayAccess.add(newarray);

        return true;
    }

    /**
     * Simply collect offset values in each scope
     *
     * @param struct_access
     * @param value_sets
     */
    private boolean _findPossibleStructAccess(Map<String, Set<String>> value_sets) {
        /* memory accessed by this function */
        List<Long> addrSet;
        String scope;

        for (Map.Entry<String, Set<String>> entMapVS : value_sets.entrySet()) {
            String addr = entMapVS.getKey();

            if (addr.charAt(0) != 'V')
                continue;

            /* Get the scope name */
            scope = addr.split(" ", 0)[0];

            /* Create a List<Long> at the first time */
            addrSet = m_mapStructAccess.get(scope);
            if (addrSet == null) {
                addrSet = new ArrayList<>();
                m_mapStructAccess.put(scope, addrSet);
            }

            /* The address may be: VRSP + VRAX + 100, so we need further verification */
            String delta = m_calc.symbolicSub(addr, scope);
            if (!m_calc.isPureDigital(delta))
                continue;

            Long v = Long.decode(delta);
            if (!addrSet.contains(v)) {
                addrSet.add(v);
            }
        }
        return true;
    }

    /**
     * Find out all scopes: each pure symbolic value representing a new scope
     *
     * @param mapSMAT
     * @return
     */
    private void inferMemScopes(Map<Long, Map<String, Set<String>>> symbolic_memory_access_table) {

        List<Long> listVS;
        String scope;

        for (Map.Entry<Long, Map<String, Set<String>>> entMapSMAT : symbolic_memory_access_table.entrySet()) {
            Long line = entMapSMAT.getKey();
            Map<String, Set<String>> mapVS = entMapSMAT.getValue();
            /* WIDENING_THRESHOLD == 6, so it should hava size bigger than or equal to 4 */
            if (mapVS.size() > 4) {
                _findPossibleArrayAccess(mapVS);
            } else {
                _findPossibleStructAccess(mapVS);
            }
        }
    }

    /**
     * An array can be on local stack or passed in as a prameter
     *
     * @param possible_array_scope
     * @param all_memory_scopes
     * @return
     */
    public Set<String> inferArrayAccess() {
        Set<String> arrInfo = new HashSet<>();

        for (Map<String, List<Long>> mapArrayAccess : m_setArrayAccess) {
            List<Long> listArrayOffset = new ArrayList<>();
            String scope = "";

            for (Map.Entry<String, List<Long>> entArrayAccess : mapArrayAccess.entrySet()) {
                scope = entArrayAccess.getKey();
                listArrayOffset = entArrayAccess.getValue();
                break; // Should have only one element
            }

            // Collections.sort(listArrayOffset);
            long maxAddr = (long) Collections.max(listArrayOffset);
            long minAddr = (long) Collections.min(listArrayOffset); // Base-addrss => Scope + minAddr
            long stride = (long) listArrayOffset.get(1) - (long) listArrayOffset.get(0); // Stride

            /* Calculate up-bound */
            List<Long> listScopeVS = m_mapStructAccess.get(scope);
            long upbound = maxAddr + stride;

            /* find max lowerbound if */
            if (listScopeVS != null) {
                // Collections.sort(listScopeVS); // in asending order
                for (Long v : listScopeVS) {
                    if (v > maxAddr) {
                        upbound = v;
                        break;
                    }
                }
            }

            /* For debuging */
            String base;
            if (minAddr == 0)
                base = scope;
            else if (minAddr > 0)
                base = String.format("%s+%d", scope, minAddr);
            else
                base = String.format("%s%d", scope, minAddr);

            String msg = String.format("Base: %s, stride: %d: size in bytes: %d", base, stride, upbound - minAddr);

            arrInfo.add(msg);
        }

        return arrInfo;
    }

    /**
     * We identify struct instance passed in as a prameter.
     *
     * @param all_memory_scopes
     * @return
     */
    public Map<String, List<Long>> inferStructAccess() {
        /* Get all scopes except stack, each scope has at most one strcuture */
        Map<String, List<Long>> mapStruct = new HashMap<>();
        List<Long> listOffset;
        String scope;

        for (Map.Entry<String, List<Long>> entScopeAccess : m_mapStructAccess.entrySet()) {
            scope = entScopeAccess.getKey();

            if (scope.equals("VRSP"))
                continue;

            listOffset = entScopeAccess.getValue();
            /* Each scope should have to access at leat two memory elments */
            if (listOffset.size() < 2)
                continue;

            /* Each scope is treated as having a structure */
            mapStruct.put(scope, listOffset);
        }

        return mapStruct;
    }
}
