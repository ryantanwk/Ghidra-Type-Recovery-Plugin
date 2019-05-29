
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
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GetFG extends GhidraScript{
    @Override
    public void run()  throws CancelledException {

        Listing listing = state.getCurrentProgram().getListing();
        FunctionIterator fiter = listing.getFunctions(true);
        CodeUnitFormat cuf = getCodeUnitFormat();

        while (fiter.hasNext() && !monitor.isCancelled()) {
            Function f = fiter.next();
            String fname = f.getName();

            if (!fname.equals("main"))
                continue;

            CodeBlockModel blockModel = new BasicBlockModel(state.getCurrentProgram());
            AddressSetView addresses = f.getBody();
            CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(addresses, monitor);

            for (; iterator.hasNext();) {
                CodeBlock codeBlock = iterator.next();

                println(codeBlock.toString());
            }

        }
    }
}
