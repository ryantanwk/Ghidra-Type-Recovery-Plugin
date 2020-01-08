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
	private AddressSet codeSegRng;
	private Map<String, AccessedObject> funcAbsDomain;
	private Map<Address, CFGNode> CFG;
	
	@Override
	public void run() {
		program = state.getCurrentProgram();
		listing = program.getListing();
		language = program.getLanguage();
		FunctionIterator funcIter = listing.getFunctions(true);
		
		try {
		while(funcIter.hasNext() && !monitor.isCancelled()) { // for each function
			Function func = funcIter.next();
			String funcName = func.getName();
			AddressSetView addrSV = func.getBody();
			CodeBlockModel blkModel = new BasicBlockModel(program);
			CodeBlockIterator codeBlkIt = blkModel.getCodeBlocksContaining(addrSV,monitor);
			CFG = new HashMap<>();
			
			while (codeBlkIt.hasNext()) { // for each of Ghidra's basic code block create CFG node
				CodeBlock codeBlk = codeBlkIt.next();
				Address blkStartAddr = codeBlk.getFirstStartAddress();
				CFG.put(blkStartAddr, new CFGNode(listing,func,program,codeBlk));
			}
			
			for (CFGNode currNode : CFG.values()) { // for each CFG node set successors
				Set<CFGNode> successors = new HashSet<>();
				CodeBlock currCodeBlk = currNode.getCodeBlock();
				CodeBlockReferenceIterator it = currCodeBlk.getDestinations(monitor);
				
				while (it.hasNext()) {
					CodeBlockReference ref = it.next();
					CodeBlock nxtCodeBlk = ref.getDestinationBlock();
					Address addrStart = nxtCodeBlk.getFirstStartAddress();
					CFGNode successor = CFG.get(addrStart);
					
					if (successor != null) { successors.add(successor); }
				}
				currNode.setSuccessors(successors);
			}
			
			printf("Function name: %s entry: %s\n", func.getName(), func.getEntryPoint());
			Address funcEntryAddr = func.getEntryPoint();
			CFGNode startNode = CFG.get(funcEntryAddr);
			funcAbsDomain = startNode.traverseCFG();
			println(funcAbsDomain.toString());
			println("----------------------------------------------------------------");
		}
		} catch (Exception e) { System.err.println("Failed"); }
	}
}

class CFGNode {
	private Program program;
	private Listing listing;
	private Function func;
	private AddressSet addrSet;
	private IRInterpreter interpreter;
	public CodeBlock codeBlk;
	private Set<CFGNode> successors;
	private Map<String, AccessedObject> absEnv;
	
	public CFGNode(Listing listing, Function func, Program program, CodeBlock ghidraBlk) {
		this.program = program;
		this.listing = listing;
		this.func = func;
		this.addrSet = ghidraBlk.intersect(func.getBody());
		this.absEnv = new HashMap();
		interpreter = new IRInterpreter(program);
		codeBlk = ghidraBlk; 
	}
	
	public Map<String, AccessedObject> traverseCFG() {
		
		InstructionIterator instIt = listing.getInstructions(addrSet,true);
		
		while (instIt.hasNext()) { // process all pcodes for this node
			Instruction inst = instIt.next();
			PcodeOp[] pcodeList = inst.getPcode();
			
			for (PcodeOp currPcode : pcodeList) {
				absEnv = interpreter.process(absEnv,currPcode,inst);
			}
		}
		
		Iterator<CFGNode> successorIt = successors.iterator();
		
		if (successorIt.hasNext()) { // recursively call successors; termination: no successors
			while(successorIt.hasNext()) {
				CFGNode nextNode = successorIt.next();
				nextNode.setAbsEnv(absEnv);
				return nextNode.traverseCFG();
			}
		}
		return absEnv;
	}
	
	public void setSuccessors(Set<CFGNode> successors) { this.successors = successors; }
	
	public void setAbsEnv(Map<String, AccessedObject> absEnv) { this.absEnv = absEnv; }
	
	public Map<String, AccessedObject> getAbsEnv() { return absEnv; }
	
	public CodeBlock getCodeBlock() { return codeBlk; }
	
	public void updateAbsEnv(Map<String, AccessedObject> update) { absEnv.putAll(update); }
}

class IRInterpreter extends Interpreter {
	private static VSACalculator calc;
	private static Program program;
	private static Language language;
	Map<String, AccessedObject> absEnv;
	
	public IRInterpreter(Program program) {
		calc = new VSACalculator();
		this.program = program;
		this.language = program.getLanguage();
	}
	
	public Map<String, AccessedObject> process(Map<String, AccessedObject> absEnv, PcodeOp pcode, Instruction inst) {
		this.absEnv = absEnv;
		String op = pcode.getMnemonic();
		
		if (op.equalsIgnoreCase("INT_NEGATE")) {_recordintneg(pcode,inst);}
		else if (op.equalsIgnoreCase("INT_ADD")) {_recordintadd(pcode,inst);}
        else if (op.equalsIgnoreCase("INT_SUB")) {_recordintsub(pcode,inst);}
        else if (op.equalsIgnoreCase("INT_MULT")) {_recordintmult(pcode,inst);}
        else if (op.equalsIgnoreCase("INT_DIV")) {_recordintdiv(pcode,inst);}
        else if (op.equalsIgnoreCase("STORE")) {_recordstore(pcode,inst);}
        else if (op.equalsIgnoreCase("LOAD")) {_recordload(pcode,inst);}
        else if (op.equalsIgnoreCase("COPY")) {_recordcopy(pcode,inst);}
        
		return absEnv;
	}
	
	private void _recordintneg(PcodeOp pcode, Instruction inst) {
    	Varnode varnode = pcode.getInput(0);
    	String resultID = uniqID(pcode.getOutput());
    	
    	// input varnode is constant
    	if (varnode.isConstant()) {
    		int value = Integer.decode(varnode.toString(language));
    		absEnv.put(resultID, toAccObj(1,-value,-value,pcode.getOutput()));
    	}  
    	
    	// input varnode is register 
    	else if (varnode.isRegister()) {
    		AccessedObject obj = getVar(varnode.toString(language));
    		
    		if (obj == null) { absEnv.put(resultID, new AccessedObject(-1)); }
    		
    		else { absEnv.put(resultID,calc.intMult(obj, -1)); }
    	}
    	
    	// input varnode is variable
    	else {
    		AccessedObject obj = getVar(Integer.toString(varnode.hashCode()));
    		
    		if (obj == null) { absEnv.put(resultID, new AccessedObject(-1)); }
    		
    		else { absEnv.put(resultID,calc.intMult(obj, -1)); }
    	}
    }
	
    private void _recordintadd(PcodeOp pcode, Instruction inst) {
    	Varnode varnode0 = pcode.getInput(0), varnode1 = pcode.getInput(1);
    	String resultID = uniqID(pcode.getOutput());
    	AccessedObject vVar0, vVar1;
		
    	if (varnode0.isConstant()) {
    		int const0 = Integer.decode(varnode0.toString(language));

    		if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language));
    			absEnv.put(resultID, toAccObj(1,const0+const1, const0+const1,pcode.getOutput()));
    		}	
    		else if (varnode1.isRegister()) { 
    			vVar1 = getVar(varnode1.toString(language));
    			absEnv.put(resultID, calc.intAdd(vVar1, const0));
    		}
    		else { 
    			vVar1 = getVar(Integer.toString(varnode1.hashCode()));
    			absEnv.put(resultID, calc.intAdd(vVar1, const0));
    		}
    	}
    	else if (varnode0.isRegister()) { // first input is register 
    		vVar0 = getVar(varnode0.toString(language));
			
    		if (varnode1.isConstant()) { 
    			//int const1 = Integer.decode(varnode1.toString(language)); // ERROR HERE
    			//absEnv.put(resultID,calc.intAdd(vVar0, const1));
    		}
    		else if (varnode1.isRegister()) {
    			vVar1 = getVar(varnode1.toString(language));
    			absEnv.put(resultID,calc.intAdd(vVar0, vVar1));
    		} 
    		else { 
    			vVar1 = getVar(Integer.toString(varnode1.hashCode()));
    			absEnv.put(resultID,calc.intAdd(vVar0, vVar1));
    		}
    	}
    	else { // first input is variable
    		vVar0 = getVar(Integer.toString(varnode0.hashCode()));
			
			if (varnode1.isConstant()) { 
    			//int const1 = Integer.decode(varnode1.toString(language));
    			//absEnv.put(resultID,calc.intAdd(vVar0, const1));
    		} 	
    		else if (varnode1.isRegister()) {
    			vVar1 = getVar(varnode1.toString(language));
    			absEnv.put(resultID,calc.intAdd(vVar0, vVar1));
    		} 
    		else { 
    			vVar1 = getVar(Integer.toString(varnode1.hashCode()));
    			absEnv.put(resultID,calc.intAdd(vVar0, vVar1));
    		}
    	}
    }
    
    private void _recordintsub(PcodeOp pcode, Instruction inst) {
    	Varnode varnode0 = pcode.getInput(0), varnode1 = pcode.getInput(1);
    	String resultID = uniqID(pcode.getOutput());
    	AccessedObject vVar0, vVar1;
		
    	if (varnode0.isConstant()) {
    		int const0 = Integer.decode(varnode0.toString(language));

    		if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language));
    			absEnv.put(resultID, toAccObj(1,const0-const1, const0-const1, pcode.getOutput()));
    		}	
    		else if (varnode1.isRegister()) { 
    			vVar1 = getVar(varnode1.toString(language));
    			absEnv.put(resultID, calc.intSub(vVar1, const0));
    		}
    		else { 
    			vVar1 = getVar(Integer.toString(varnode1.hashCode()));
    			absEnv.put(resultID, calc.intSub(vVar1, const0));
    		}
    	}
    	else if (varnode0.isRegister()) { // first input is register 
    		vVar0 = getVar(varnode0.toString(language));
			
    		if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language)); // ERROR HERE
    			absEnv.put(resultID,calc.intSub(vVar0, const1));
    		}
    		else if (varnode1.isRegister()) {
    			vVar1 = getVar(varnode1.toString(language));
    			absEnv.put(resultID,calc.intSub(vVar0, vVar1));
    		} 
    		else { 
    			vVar1 = getVar(Integer.toString(varnode1.hashCode()));
    			absEnv.put(resultID,calc.intSub(vVar0, vVar1));
    		}
    	}
    	else { // first input is variable
    		vVar0 = getVar(Integer.toString(varnode0.hashCode()));
			
			if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language));
    			absEnv.put(resultID,calc.intSub(vVar0, const1));
    		} 	
    		else if (varnode1.isRegister()) {
    			vVar1 = getVar(varnode1.toString(language));
    			absEnv.put(resultID,calc.intSub(vVar0, vVar1));
    		} 
    		else { 
    			vVar1 = getVar(Integer.toString(varnode1.hashCode()));
    			absEnv.put(resultID,calc.intSub(vVar0, vVar1));
    		}
    	}
    }
    
    private void _recordintmult(PcodeOp pcode, Instruction inst) {
    	Varnode varnode0 = pcode.getInput(0), varnode1 = pcode.getInput(1);
    	String resultID = uniqID(pcode.getOutput());
    	AccessedObject vVar0, vVar1;
		
    	if (varnode0.isConstant()) {
    		int const0 = Integer.decode(varnode0.toString(language));

    		if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language));
    			absEnv.put(resultID, toAccObj(1,const0*const1, const0*const1, pcode.getOutput()));
    		}	
    		else if (varnode1.isRegister()) { 
    			vVar1 = getVar(varnode1.toString(language));
    			absEnv.put(resultID, calc.intMult(vVar1, const0));
    		}
    		else { 
    			vVar1 = getVar(Integer.toString(varnode1.hashCode()));
    			absEnv.put(resultID, calc.intMult(vVar1, const0));
    		}
    	}
    	else if (varnode0.isRegister()) { // first input is register 
    		vVar0 = getVar(varnode0.toString(language));
			
    		if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language));
    			absEnv.put(resultID, calc.intMult(vVar0, const1));
    		} 	
    		else { absEnv.put(resultID, new AccessedObject(-1)); }
    	}
    	else {
    		vVar0 = getVar(Integer.toString(varnode1.hashCode()));
    		
    		if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language));
    			absEnv.put(resultID, calc.intMult(vVar0, const1));
    		} 	
    		else { absEnv.put(resultID, new AccessedObject(-1)); }
    	}
    }
    
    private void _recordintdiv(PcodeOp pcode, Instruction inst) {
    	Varnode varnode0 = pcode.getInput(0), varnode1 = pcode.getInput(1);
    	String resultID = uniqID(pcode.getOutput());
    	AccessedObject vVar0, vVar1;
		
    	if (varnode0.isConstant()) {
    		int const0 = Integer.decode(varnode0.toString(language));

    		if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language));
    			absEnv.put(resultID, toAccObj(1,const0/const1, const0/const1, pcode.getOutput()));
    		}	
    		else if (varnode1.isRegister()) { 
    			vVar1 = getVar(varnode1.toString(language));
    			absEnv.put(resultID, calc.intDiv(vVar1, const0));
    		}
    		else { 
    			vVar1 = getVar(Integer.toString(varnode1.hashCode()));
    			absEnv.put(resultID, calc.intDiv(vVar1, const0));
    		}
    	}
    	else if (varnode0.isRegister()) { // first input is register 
    		vVar0 = getVar(varnode0.toString(language));
			
    		if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language));
    			absEnv.put(resultID, calc.intDiv(vVar0, const1));
    		} 	
    		else { absEnv.put(resultID, new AccessedObject(-1)); }
    	}
    	else {
    		vVar0 = getVar(Integer.toString(varnode1.hashCode()));
    		
    		if (varnode1.isConstant()) { 
    			int const1 = Integer.decode(varnode1.toString(language));
    			absEnv.put(resultID, calc.intDiv(vVar0, const1));
    		} 	
    		else { absEnv.put(resultID, new AccessedObject(-1)); }
    	}
    }
    
    //input0 	(special) Constant ID of space to store into.
    //input1	Varnode containing pointer offset of destination.
    //input2 	Varnode containing data to be stored.
    private void _recordstore(PcodeOp pcode,Instruction inst) {
    	
    	String resultID = pcode.getInput(0).toString(language) + "+" + pcode.getInput(1).toString(language);
    	
    	AccessedObject value = absEnv.get(resultID);
    	
    	if(value != null) { absEnv.put(resultID,value); }
    	
    	/*Varnode varnode2 = pcode.getInput(2);
    	String resultID = uniqID(pcode.getInput(0),pcode.getInput(1));
    	AccessedObject vVarSrc;
    	vVarSrc = getVar(uniqID(varnode2));
    	absEnv.put(resultID, vVarSrc);*/
    }

    //input0 	(special) Constant ID of space to store into.
    //input1	Varnode containing pointer offset of destination.
    //output 	Destination varnode.
    private void _recordload(PcodeOp pcode, Instruction inst) {
    	Varnode varnode0 = pcode.getInput(0), varnode1 = pcode.getInput(1), varnode3 = pcode.getOutput();
    	String resultID = uniqID(varnode3);
    	AccessedObject vVarSrc;
    	vVarSrc = getVar(uniqID(varnode0,varnode1));
    	absEnv.put(resultID, vVarSrc);
    }
    
    private void _recordcopy(PcodeOp pcode, Instruction inst) {
    	
    	Varnode varnode = pcode.getInput(0), outputVar = pcode.getOutput();
		Address addr = varnode.getAddress();
    	long offset = addr.getOffset();
    	AddressSpace addrSpace = addr.getAddressSpace();
    	int spaceID = addrSpace.getBaseSpaceID();
    	String resultID = Integer.toString(spaceID) + "+" + Long.toString(offset);
		
    	if (varnode.isConstant()) { 
    		int value = Integer.decode(varnode.toString(language));
    		absEnv.put(resultID, toAccObj(1,value,value,outputVar));
    	}
    	
    	/*Varnode varnode = pcode.getInput(0), output = pcode.getOutput();
    	String resultID = uniqID(output);
		
    	if (varnode.isConstant()) { 
    		int value = Integer.decode(varnode.toString(language));
    		absEnv.put(resultID, toAccObj(1,value,value, output));
    	}
    	else if (varnode.isRegister()) { absEnv.put(resultID,getVar(varnode.toString(language))); } 
    	else { absEnv.put(resultID,getVar(Integer.toString(varnode.hashCode()))); }*/
    }
    
    private AccessedObject getVar(String ID) { 
    	if (absEnv.containsKey(ID)) { return absEnv.get(ID); }
    	
    	return new AccessedObject(-1);
    }
    
    private AccessedObject toAccObj(int stride, int lwr, int upp, Varnode node) {
    	Address addr = node.getAddress();
    	
    	return new AccessedObject(stride,lwr, upp, node.getSize(), node.getOffset(),addr.toString());
    }
    
    private String uniqID(Varnode var) {
    	Address addr = var.getAddress();
    	long offset = addr.getOffset();
    	AddressSpace addrSpace = addr.getAddressSpace();
    	int spaceID = addrSpace.getBaseSpaceID();
    	String result = Integer.toString(spaceID) + "+" + Long.toString(offset);
    	return result;
    }
    private String uniqID(Varnode ID, Varnode offset) {
    	String result = ID.toString(language) + "+" + offset.toString(language);
    	return result;
    }
}

//maps a varnode hashCode to its strided interval
class AccessedObject {
public int stride, lwrBnd, uppBnd, size;
public long offset;
public String address;

	public AccessedObject(int value) { stride = value; }
	
	public AccessedObject(int stride, int lwrBnd, int uppBnd, int size, 
			long offset, String address) {
		
		this.stride = stride;
		this.lwrBnd = lwrBnd;
		this.uppBnd = uppBnd;
		this.size = size;
		this.offset = offset;
		this.address = address;
		
	}
	public String toString() {
		if (stride == -1) 
			return "Unknown";
		String printable = String.format("Offset: " + Long.toString(offset) + " Size: " + 
			Integer.toString(size) + " Interval: " + Integer.toString(stride) + "[" + 
				Integer.toString(lwrBnd) + "," + Integer.toString(uppBnd) + "]");
		return printable;
	}
	public boolean diffInStride(int dst, int value) {
		if (((dst-value)%stride) == 0) {return true;}
		return false;
	}
	public AccessedObject(AccessedObject copy) {
		this.stride = copy.stride;
		this.lwrBnd = copy.lwrBnd;
		this.uppBnd = copy.uppBnd;
	}
	public void unknown() {this.stride = -1;}
	public boolean isUnknown() {return stride == -1;}
}

/* does strided interval arithmetics */
class VSACalculator {

	public AccessedObject intAdd(AccessedObject arg0, int constant) {
		if (arg0.stride == -1) { return arg0; }
		
		arg0.lwrBnd = arg0.lwrBnd + constant;
		arg0.uppBnd = arg0.uppBnd + constant;
		return arg0;
	}
	
	// returns String representation of strided interval of arg0 after SI int add
	public AccessedObject intAdd(AccessedObject arg0, AccessedObject arg1) {
		if (arg0.stride == -1 || arg1.stride == -1) { return arg0; }
		
		if ((arg1.stride % arg0.stride) == 0) { // strides of src is a multiple of stride of dst
			arg0.lwrBnd = arg0.lwrBnd + arg1.lwrBnd;
			arg0.uppBnd = arg0.uppBnd + arg1.uppBnd;
		}
		else if ((arg0.stride % arg1.stride) == 0) { // stride of dst is a multiple of stride of src
			int factor = arg0.stride/arg1.stride, numSrcVal = (arg1.uppBnd-arg1.lwrBnd)/arg1.stride, 
					uppBndAdded = arg1.uppBnd, lwrBndAdded = arg1.lwrBnd;
			
			if (numSrcVal < factor) { // num values of src < (dst/src)
				arg0.stride = 0;
				return arg0;
			}
			
			int curVal = arg1.lwrBnd;
			for (int i = 0 ; i < numSrcVal ; i++) { // set uppBndAdded to largest value in src with a strided difference from dst.uppBnd
				curVal = curVal + i*arg0.stride;
				if (arg0.diffInStride(arg0.uppBnd,curVal))
					uppBndAdded = curVal;
			}
			curVal = arg0.lwrBnd;
			for (int i = 0 ; i < numSrcVal ; i++) { // set uppBndAdded as smallest value in src with a strided difference from dst.lwrBnd
				curVal = curVal + i*arg0.stride;
				if (arg0.diffInStride(arg1.lwrBnd,curVal)) {
					lwrBndAdded = curVal;
					break;
				}
			}
			arg0.uppBnd += uppBndAdded;
			arg0.lwrBnd += lwrBndAdded;
		}
		else {
			arg0.stride = -1;
		}
		return arg0;
	}
	
	public AccessedObject intSub(AccessedObject arg0, int constant) {
		if (arg0.stride == -1) { return arg0; }
		
		arg0.lwrBnd = arg0.lwrBnd - constant;
		arg0.uppBnd = arg0.uppBnd - constant;
		return arg0;
	}
	
	public AccessedObject intSub(AccessedObject arg0, AccessedObject arg1) {
		if (arg0.stride == -1 || arg1.stride == -1) { return arg0; }
		
		if ((arg1.stride % arg0.stride) == 0) { // strides of src is a multiple of stride of dst
			arg0.lwrBnd -= arg1.uppBnd;
			arg0.uppBnd -= arg1.lwrBnd;
		}
		else if ((arg0.stride % arg1.stride) == 0) { // stride of dst is a multiple of stride of src
			int factor = arg0.stride/arg1.stride, numSrcVal = (arg1.uppBnd-arg1.lwrBnd)/arg1.stride, 
					uppBndSub = arg1.uppBnd, lwrBndSub = arg1.lwrBnd;
			
			if (numSrcVal < factor) { // num values of src < (dst/src)
				arg0.stride = -1;
				return arg0;
			}
			int curVal = arg1.lwrBnd;
			for (int i = 0 ; i < numSrcVal ; i++) { // set lwrBndSub to largest value in src with a strided difference from dst.uppBnd
				curVal = curVal + i*arg1.stride;
				if (arg0.diffInStride(arg0.lwrBnd,curVal))
					lwrBndSub = curVal;
			}
			curVal = arg1.lwrBnd;
			for (int i = 0 ; i < numSrcVal ; i++) { // set uppBndASub as smallest value in src with a strided difference from dst.lwrBnd
				curVal = curVal + i*arg1.stride;
				if (arg0.diffInStride(arg0.uppBnd,curVal)) {
					uppBndSub = curVal;
					break;
				}
			}
			arg0.lwrBnd -= lwrBndSub;
			arg0.uppBnd -= uppBndSub;
		}
		else {
			arg0.stride = -1;
		}
		return arg0;
	}
	
	public AccessedObject intMult(AccessedObject arg0, int magnitude) { //TO-DO
		if (arg0.stride == -1) { return arg0; }
		
		arg0.lwrBnd *= magnitude;
		arg0.uppBnd *= magnitude;
		arg0.stride *= magnitude;
		return arg0;
	}
	
	public AccessedObject intDiv(AccessedObject arg0, int magnitude) { //TO-DO
		
		if (arg0.stride == -1) { return arg0; }
		
		if (arg0.lwrBnd%magnitude == 0 && arg0.uppBnd%magnitude == 0 && arg0.stride%magnitude == 0) {
			arg0.lwrBnd /= magnitude;
			arg0.uppBnd /= magnitude;
			arg0.stride /= magnitude;
		}
		else {
			arg0.stride = -1;
		}
		return arg0;
	}
}
