import java.io.IOException;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*; // Map & List
import java.util.concurrent.CopyOnWriteArrayList;
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

public class VSA_TypeRecReq extends GhidraScript {
	private Program program;
	private Listing listing;
	private Language language;
	private AddressSet codeSegRng;
	private Hashtable<String, AccessedObject> funcAbsDomain = new Hashtable<String,AccessedObject>(); // Key:AccessedObject.location
	
	@Override
	public void run() {
		program = state.getCurrentProgram();
		listing = program.getListing();
		language = program.getLanguage();
		FunctionIterator funcIter = listing.getFunctions(true);
		IRInterpreter interpreter = new IRInterpreter(program);
		int pcodeCtr = 0;
		
		try {
		FileWriter writer = new FileWriter("/home/shruti/NUS/type-inference/MyFile.txt", false);
    	PrintWriter printWriter = new PrintWriter(writer);
			
		while(funcIter.hasNext() && !monitor.isCancelled()) {
			Function func = funcIter.next();
			String funcName = func.getName();
			if (!funcName.equals("main")) {continue;} // function selection

			printf("Function name: %s entry: %s\n", func.getName(), func.getEntryPoint());
			
			AddressSetView addrSV = func.getBody();
			InstructionIterator iiter = listing.getInstructions(addrSV,true);
			String printable;
			
			while (iiter.hasNext()) { // for each machine instruction
				Instruction inst = iiter.next();
				PcodeOp[] pcodeList = inst.getPcode(); 
				
				for (PcodeOp currPcode : pcodeList) { // for each pcode
					pcodeCtr++;
					printable = currPcode.getMnemonic();
						
					for (int i = 0 ; i < currPcode.getNumInputs() ; i ++) {
						Varnode input = currPcode.getInput(i);
						if (input.isConstant()) {
							printable = printable.concat(" " + input.toString(language));
						}
						else {
							AccessedObject target = get(input);
							printable = printable.concat(" (" + target.toString() + ")");
						}
					}
						
					funcAbsDomain = interpreter.process(funcAbsDomain,currPcode,inst);
					Varnode output = currPcode.getOutput();
					if (output != null) {
						AccessedObject targetOutput = get(output);
						printable = printable.concat(" = " + targetOutput.toString());
					}
					printWriter.write(printable); // print to file
	    			printWriter.write("\n"); // print to file
				}
			}
			println("-----------------------------------END-----------------------------------");
		}
		} catch (Exception e) { System.err.println("Failed"); }
	}
    public AccessedObject get(Varnode varnode) {
    	AccessedObject returnable;
    	
    	if (varnode.isRegister()) {
    		returnable = funcAbsDomain.get(varnode.toString(language));
    		if (returnable == null) {
    			returnable = new AccessedObject(1,0,0,varnode.getSize(),varnode.toString(language));
    			returnable.symbolic = varnode.toString(language);
    			funcAbsDomain.put(returnable.location,returnable);
    		}
    	}
    	else {
    		returnable = funcAbsDomain.get(Long.toString(varnode.getOffset()));
    		if (returnable == null) { 
    			returnable = new AccessedObject(-1,0,0,varnode.getSize(),
    				Long.toString(varnode.getOffset())); 
    			funcAbsDomain.put(returnable.location,returnable);
    		}
    	}
    	
    	return returnable;
    }
}

class IRInterpreter extends Interpreter {
	private static VSACalculator calc;
	private static Program program;
	private static Language language;
	Hashtable<String, AccessedObject> absEnv; // key : varnode hashcode || value : AccessedObject
	
	public IRInterpreter(Program program) {
		calc = new VSACalculator();
		this.program = program;
		this.language = program.getLanguage();
	}
	
	public Hashtable<String, AccessedObject> process(Hashtable<String, AccessedObject> absEnv, PcodeOp pcode, Instruction inst) {
		this.absEnv = absEnv;
		String op = pcode.getMnemonic();
		
		if (op.equalsIgnoreCase("INT_NEGATE")) {_recordintneg(pcode);}
		else if (op.equalsIgnoreCase("INT_ADD")) {_recordintadd(pcode);}
		else if (op.equalsIgnoreCase("INT_SUB")) {_recordintsub(pcode);}
        else if (op.equalsIgnoreCase("INT_MULT")) {_recordintmult(pcode);}
        else if (op.equalsIgnoreCase("INT_DIV")) {_recordintdiv(pcode);}
        else if (op.equalsIgnoreCase("STORE")) {_recordstore(pcode);}
        else if (op.equalsIgnoreCase("LOAD")) {_recordload(pcode);}
		else if (op.equalsIgnoreCase("COPY")) {_recordcopy(pcode);}
        else {_recordunknown(pcode);}
        
		return absEnv;
	}
	
	private void _recordintneg(PcodeOp pcode) {
    	Varnode input0 = pcode.getInput(0), output = pcode.getOutput();
    	AccessedObject target, tmp = null;
    	
    	if (input0.isConstant()) { // input0 is constant
    		int value = Integer.decode(input0.toString(language)); // get const value
    		target = new AccessedObject(1,-value,-value,input0.getSize(), 
    				Long.toString(input0.getOffset())); // create new AccessedObject
    	}
    	else { // input is var || reg
    		target = get(input0); // retrieve || create AccessedObject
    		tmp = target.getCopy(); // create new AccessedObject to work on
    		target = calc.intMult(tmp, -1); // negate tmp stored value and set to target
    	}
    	target = set(target,output,false); // set output's location to target
    	absEnv.put(target.location,target); // put target into the table, overriding exisiting entry with same key if it exists
    }
	
    private void _recordintadd(PcodeOp pcode) {
    	Varnode input0 = pcode.getInput(0), input1 = pcode.getInput(1), output = pcode.getOutput();
    	AccessedObject input0AO, input1AO, target = null, tmp0 = null, tmp1 = null;
    	
    	if (input0.isConstant()) { // input0 is constant
    		int value0 = new BigInteger(input0.toString(language).substring(2),16).intValue(); // get const value
    		
    		if (input1.isConstant()) { // input1 is constant
    			int value1 = new BigInteger(input1.toString(language).substring(2),16).intValue(); // get const value
    			
    			target = new AccessedObject(1,value0+value1,value0+value1,input0.getSize(),
    					Long.toString(input0.getOffset())); // create AccessedObject
    		}
    		else {
    			input1AO = get(input1); // input1 is var || reg
    			tmp1 = input1AO.getCopy(); // create new AccessedObject to work on
    			target = calc.intAdd(tmp1, value0); // arithmetic
    		}
    	}
    	else { // input0 is var || reg
    		input0AO = get(input0); // retrieve || create AccessedObject
    		tmp0 = input0AO.getCopy(); // create new AccessedObject to work on
    		input0AO = tmp0;
    		if (input1.isConstant()) { // input1 is constant
    			int value1 = new BigInteger(input1.toString(language).substring(2),16).intValue();
    			target = calc.intAdd(input0AO, value1); // airthmetric
    		}
    		else { // input1 is var || reg
    			input1AO = get(input1); // retrieve || create AccessedObject
    			tmp1 = input1AO.getCopy(); // create new AccessedObject to work on
    			input1AO = tmp1;
    			target = calc.intAdd(input0AO, input1AO); // arithmetic ;
    		}
    	}
    	target = set(target,output,false);
    	absEnv.put(target.location,target);
    }
    
    private void _recordintsub(PcodeOp pcode) {
    	Varnode input0 = pcode.getInput(0), input1 = pcode.getInput(1), output = pcode.getOutput();
    	AccessedObject input0AO, input1AO, target = null, tmp0 = null, tmp1 =null;
    	
    	if (input0.isConstant()) {
    		int value0 = new BigInteger(input0.toString(language).substring(2),16).intValue();
    		
    		if (input1.isConstant()) {
    			int value1 = new BigInteger(input1.toString(language).substring(2),16).intValue();
    			
    			target = new AccessedObject(1,value0-value1,value0-value1,input0.getSize(),
    					Long.toString(input0.getOffset()));
    		}
    		else {
    			input1AO = get(input1);
    			tmp1 = input1AO.getCopy(); // create new AccessedObject to work on
    			input1AO = tmp1;
    			target = calc.intSub(input1AO, value0);
    		}
    	}
    	else {
    		input0AO = get(input0);
    		tmp0 = input0AO.getCopy(); // create new AccessedObject to work on
    		input0AO = tmp0;
    		if (input1.isConstant()) {
    			int value1 = new BigInteger(input1.toString(language).substring(2),16).intValue();
    			target = calc.intSub(input0AO, value1);
    		}
    		else {
    			input1AO = get(input1);
    			tmp1 = input1AO.getCopy(); // create new AccessedObject to work on
    			input1AO = tmp1;
    			target = calc.intSub(input0AO, input1AO);
    		}
    	}
    	target = set(target,output,false);
    	absEnv.put(target.location,target);
    }
    
    private void _recordintmult(PcodeOp pcode) {
    	Varnode input0 = pcode.getInput(0), input1 = pcode.getInput(1), output = pcode.getOutput();
    	AccessedObject input0AO, input1AO, target, tmp0 = null, tmp1 = null;
		
    	if (input0.isConstant()) {
    		int value0 = new BigInteger(input0.toString(language).substring(2),16).intValue();
    		
    		if (input1.isConstant()) {
    			int value1 = new BigInteger(input1.toString(language).substring(2),16).intValue();
    			
    			target = new AccessedObject(1,value0*value1,value0*value1,input0.getSize(),
    					Long.toString(input0.getOffset()));
    		}
    		else {
    			input1AO = get(input1);
    			tmp1 = input1AO.getCopy(); // create new AccessedObject to work on
    			input1AO = tmp1;
    			target = calc.intMult(input1AO, value0);
    		}
    	}
    	else {
    		input0AO = get(input0);
    		tmp0 = input0AO.getCopy(); // create new AccessedObject to work on
    		input0AO = tmp0;
    		if (input1.isConstant()) {
    			int value1 = new BigInteger(input1.toString(language).substring(2),16).intValue();
    			
    			target = calc.intMult(input0AO, value1);
    		}
    		else {
    			target = new AccessedObject(-1,0,0,input0.getSize(),Long.toString(input0.getOffset()));
    		}
    	}
    	target = set(target,output,false);
    	absEnv.put(target.location,target);
    }
    
    private void _recordintdiv(PcodeOp pcode) {
    	Varnode input0 = pcode.getInput(0), input1 = pcode.getInput(1), output = pcode.getOutput();
    	AccessedObject input0AO, input1AO, target, tmp0 = null, tmp1 = null;
		
    	if (input0.isConstant()) {
    		int value0 = new BigInteger(input0.toString(language).substring(2),16).intValue();
    		
    		if (input1.isConstant()) {
    			int value1 = new BigInteger(input1.toString(language).substring(2),16).intValue();
    			
    			target = new AccessedObject(1,value0/value1,value0/value1,input0.getSize(),
    					Long.toString(input0.getOffset()));
    		}
    		else {
    			input1AO = get(input1);
    			tmp1 = input1AO.getCopy(); // create new AccessedObject to work on
    			input1AO = tmp1;
    			target = calc.intDiv(input1AO, value0);
    		}
    	}
    	else {
    		input0AO = get(input0);
    		tmp0 = input0AO.getCopy(); // create new AccessedObject to work on
    		input0AO = tmp0;
    		if (input1.isConstant()) {
    			int value1 = new BigInteger(input1.toString(language).substring(2),16).intValue();
    			
    			target = calc.intDiv(input0AO, value1);
    		}
    		else {
    			target = new AccessedObject(-1,0,0,input0.getSize(),Long.toString(input0.getOffset()));
    		}
    	}
    	target = set(target,output,false);
    	absEnv.put(target.location,target);
    }
    
    //input0 	(special) Constant ID of space to store into.
    //input1	Varnode containing pointer offset of destination.
    //input2 	Varnode containing data to be stored.
    private void _recordstore(PcodeOp pcode) {
    	Varnode input1 = pcode.getInput(1), input2 = pcode.getInput(2);
    	AccessedObject input1AO = get(input1), input2AO = get(input2), result;
    	
    	result = new AccessedObject(input2AO.stride,input2AO.lwrBnd,input2AO.uppBnd,
    			input2AO.size,input1AO.dataAsLoc());
    	
    	if (input2AO.symbolic != null) { result.symbolic = input2AO.symbolic; }
    	
    	absEnv.put(input1AO.dataAsLoc(),result);
    }

    //input0 	(special) Constant ID of space to store into.
    //input1	Varnode containing pointer offset of source.
    //output 	Destination varnode.
    private void _recordload(PcodeOp pcode) {
    	Varnode input1 = pcode.getInput(1), output = pcode.getOutput();
    	AccessedObject input1AO = get(input1),result,src;
    	
    	if (input1.isRegister()) {
    		src = get(input1.toString(language)); 
    		if (src.lwrBnd != 0 || src.uppBnd != 0) { src = get(input1AO.dataAsLoc()); }
    	}
    	else {src = get(input1AO.dataAsLoc());}
    	
    	
    	result = src.getCopy();
    	AccessedObject outputAO = get(output);
    	result.location = outputAO.location;
    	absEnv.put(result.location,result);
    }
    
    private void _recordcopy(PcodeOp pcode) {
    	Varnode input0 = pcode.getInput(0), output = pcode.getOutput();
    	AccessedObject result = null;
    	
    	if (input0.isConstant()) {  // input is constant 
    		int value0 = new BigInteger(input0.toString(language).substring(2),16).intValue();
    		result = new AccessedObject(1,value0,value0,output.getSize(),"");
    	}
    	else if (input0.isRegister()) { // input is register
    		if (absEnv.containsKey(input0.toString(language))) { // input exists in absEnv
    			result = absEnv.get(input0.toString(language)).getCopy();
    		}
    		else { // input does not exist in absEnv
    			AccessedObject tmp = new AccessedObject(1,0,0,input0.getSize(),input0.toString(language));
    			tmp.symbolic = input0.toString(language);
    			absEnv.put(tmp.location, tmp);
    			result = tmp.getCopy();
    		}
    	}
    	else { // input is var 
    		if (absEnv.containsKey(Long.toString(input0.getOffset()))) { // input exists in absEnv
    			result = absEnv.get(Long.toString(input0.getOffset())).getCopy();
    		}
    		else { // input does not exist in absEnv
    			AccessedObject tmp = new AccessedObject(1,0,0,input0.getSize(),Long.toString(input0.getOffset()));
    			tmp.symbolic = input0.toString(language);
    			absEnv.put(tmp.location, tmp);
    			result = tmp.getCopy();
    		}
    	}
    	
    	// set location of result to output
    	if (output.isRegister()) {result.location = output.toString(language);}
    	else {result.location = Long.toString(output.getOffset());}
    	
    	absEnv.put(result.location,result);
    }
    
    private void _recordunknown(PcodeOp pcode) { 
    	try {
    		Varnode output = pcode.getOutput();
    		AccessedObject result = get(output);
    		absEnv.put(result.location,result);
    	} catch(Exception e) {}
    }
    
    /*
     * Set location of AccessedObject to output's appropriate location & combine symbolic values
     */
    private AccessedObject set(AccessedObject target, Varnode output,boolean isLoad) {
    	AccessedObject dst = get(output);
    	target.location = dst.location;
    	return target;
    }
    
    /*
     * Retrieve AccessedObject associate to input from absEnv
     * OR
     * Create a new AccessedObject for input, put into absEnv & return AccessedObject
     */
    public AccessedObject get(Varnode varnode) {
    	AccessedObject returnable;
    	
    	if (varnode.isRegister()) {
    		returnable = absEnv.get(varnode.toString(language));
    		if (returnable == null) {
    			returnable = new AccessedObject(1,0,0,varnode.getSize(),varnode.toString(language));
    			returnable.symbolic = varnode.toString(language);
    			absEnv.put(returnable.location,returnable);
    		}
    	}
    	else {
    		returnable = absEnv.get(Long.toString(varnode.getOffset()));
    		if (returnable == null) { 
    			returnable = new AccessedObject(-1,0,0,varnode.getSize(),
    				Long.toString(varnode.getOffset())); 
    			absEnv.put(returnable.location,returnable);
    		}
    	}
    	
    	return returnable;
    }
    
    private AccessedObject get(String ID) {
    	AccessedObject returnable = absEnv.get(ID);
    	
    	if (returnable == null) {
    		returnable = new AccessedObject(-1,0,0,0,ID);
    	}
    	return returnable;
    }
}

//maps a varnode hashCode to its strided interval
class AccessedObject {
public int stride, lwrBnd, uppBnd, size;
public String symbolic = null;
public String location; // strided interval || symbolic || symbolic + strided interval

	public AccessedObject(int stride, int lwrBnd, int uppBnd, int size, String location) {
		this.stride = stride;
		this.lwrBnd = lwrBnd;
		this.uppBnd = uppBnd;
		this.size = size;
		this.location = location;
	}
	public String toString() {
		String printable;
		if (stride == -1) {
			if (symbolic == null) {
				printable = String.format("Location:" + location + " Size:" + 
						Integer.toString(size) + " Interval:Unknown");
			}
			else {
				printable = String.format("Location:" + location + " Size:" + 
						Integer.toString(size) + " Interval:" + symbolic + " + Unknown");
			}
		}
		else if (symbolic != null) {
			printable = String.format("Location:" + location + " Size:" + 
					Integer.toString(size) + " Interval:" + symbolic + "+" + Integer.toString(stride) + 
					"[" + Integer.toString(lwrBnd) + "," + Integer.toString(uppBnd) + "]");
		}
		else {
			printable = String.format("Location:" + location + " Size:" + 
				Integer.toString(size) + " Interval:" + Integer.toString(stride) + 
				"[" + Integer.toString(lwrBnd) + "," + Integer.toString(uppBnd) + "]");
		} 
		return printable;
	}
	public String dataAsLoc() {
		String loc;
		if (symbolic == null) {
			loc = String.format(Integer.toString(stride) + "[" + Integer.toString(lwrBnd) + 
					"," + Integer.toString(uppBnd) + "]");
		}
		else {
			loc = String.format(symbolic + "+" + Integer.toString(stride) + "[" + 
					Integer.toString(lwrBnd) + "," + Integer.toString(uppBnd) + "]");
		}
		return loc;
	}
	public String SIString() {
		String result = String.format(Integer.toString(stride) + 
				"[" + Integer.toString(lwrBnd) + "," + Integer.toString(uppBnd) + "]");
		return result;
	}
	public boolean diffInStride(int dst, int value) {
		if (((dst-value)%stride) == 0) {return true;}
		return false;
	}
	public AccessedObject getCopy() {
		AccessedObject tmp = new AccessedObject(stride,lwrBnd,uppBnd,size,location);
		tmp.symbolic = symbolic;
		return tmp;
	}
	public void unknown() {this.stride = -1;}
	public boolean isUnknown() {return stride == -1;}
}

/*
 * does SI arithmetic and update symbolic part but no changes to offset, size, location
 */
class VSACalculator {

	public AccessedObject intAdd(AccessedObject arg0, int constant) {
		if (arg0.stride == -1) { return arg0; }
		
		arg0.lwrBnd = arg0.lwrBnd + constant;
		arg0.uppBnd = arg0.uppBnd + constant;
		return arg0;
	}
	
	public AccessedObject intAdd(AccessedObject arg0, AccessedObject arg1) {
		
		AccessedObject returnable;
		
		// arg0 unknown
		if (arg0.stride == -1 || arg1.stride == -1) { 
			arg0.stride = -1;
			returnable = arg0; 
		}
		
		// strides of src is a multiple of stride of dst
		else if ((arg1.stride % arg0.stride) == 0) { 
			arg0.lwrBnd = arg0.lwrBnd + arg1.lwrBnd;
			arg0.uppBnd = arg0.uppBnd + arg1.uppBnd;
		}
		else if ((arg0.stride % arg1.stride) == 0) { 
			int factor = arg0.stride/arg1.stride, numSrcVal = (arg1.uppBnd-arg1.lwrBnd)/arg1.stride, 
					uppBndAdded = arg1.uppBnd, lwrBndAdded = arg1.lwrBnd;
			
			if (numSrcVal < factor) { // num values of src < (dst/src)
				arg0.stride = -1;
			}
			else {
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
		}
		else {
			arg0.stride = -1;
		}
		
		returnable = arg0;
		
    	if (arg1.symbolic != null) {
    		if (returnable.symbolic == null) { returnable.symbolic = arg1.symbolic; }
    		else {
    			String[] parts = returnable.symbolic.split("-|\\+");
    			boolean symExist = false;
    			for (int i = 0 ; i < parts.length ; i++) {
    				if (parts[i].equals(arg1.symbolic)) {symExist = true;}
    			}
    			if (!symExist) {returnable.symbolic = returnable.symbolic + "+" + arg1.symbolic;}
    		}
    	}
		return returnable;
	}
	
	public AccessedObject intSub(AccessedObject arg0, int constant) {
		if (arg0.stride == -1) { return arg0; }
		
		arg0.lwrBnd = arg0.lwrBnd - constant;
		arg0.uppBnd = arg0.uppBnd - constant;
		return arg0;
	}
	
	public AccessedObject intSub(AccessedObject arg0, AccessedObject arg1) {
		AccessedObject returnable;
		
		if (arg0.stride == -1 || arg1.stride == -1) { 
			arg0.stride = -1; 
		}
		
		if ((arg1.stride % arg0.stride) == 0) { // strides of src is a multiple of stride of dst
			arg0.lwrBnd -= arg1.uppBnd;
			arg0.uppBnd -= arg1.lwrBnd;
		}
		else if ((arg0.stride % arg1.stride) == 0) { // stride of dst is a multiple of stride of src
			int factor = arg0.stride/arg1.stride, numSrcVal = (arg1.uppBnd-arg1.lwrBnd)/arg1.stride, 
					uppBndSub = arg1.uppBnd, lwrBndSub = arg1.lwrBnd;
			
			if (numSrcVal < factor) { // num values of src < (dst/src)
				arg0.stride = -1;
			}
			else {
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
		}
		else {
			arg0.stride = -1;
		}
		
		returnable = arg0;

    	if (arg1.symbolic != null) {
    		if (returnable.symbolic == null) { returnable.symbolic = arg1.symbolic; }
    		else {
    			String[] parts = returnable.symbolic.split("-|\\+");
    			boolean symExist = false;
    			for (int i = 0 ; i < parts.length ; i++) {
    				if (parts[i].equals(arg1.symbolic)) {symExist = true;}
    			}
    			if (!symExist) {returnable.symbolic = returnable.symbolic + "-" + arg1.symbolic;}
    		}
    	}
		return returnable;
	}
	
	public AccessedObject intMult(AccessedObject arg0, int magnitude) {
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
