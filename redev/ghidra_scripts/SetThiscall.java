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


public class SetThiscall extends GhidraScript {

    @Override
    public void run() {
        Listing listing = state.getCurrentProgram().getListing();
        FunctionIterator iter = listing.getFunctions(true);

        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            String fname = f.getName();
            String oldcv = f.getCallingConventionName();
            boolean rollback = false;

            try {
                if (presumClassMethod(fname)) {
                    f.setCallingConvention("__thiscall");
                }
            }
            catch(Exception e) {
                rollback = true;
            }

            if(rollback && f.getCallingConventionName() != oldcv) {
                try {
                    f.setCallingConvention(oldcv);
                }
                catch(Exception e) {
                }
            }
        }
    }

    boolean presumClassMethod (String str) {
        boolean  isDash = false;
        boolean  isDigit = false;
        boolean  isUpcase = false;

        for (char ch : str.toCharArray()) {
            isDash |= (ch == '_');
            isDigit |= Character.isDigit(ch);
            isUpcase |= Character.isUpperCase(ch);
        }
        return isDash && isDigit && isUpcase;
    }
}
