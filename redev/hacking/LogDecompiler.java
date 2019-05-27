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
package ghidra.app.decompiler;

import java.io.IOException;

import java.util.logging.Formatter;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LogDecompiler {
	// static variable single_instance of type Singleton 
	private static LogDecompiler single_instance = null;
	private Logger log = null;
	private FileHandler fh = null;
	Formatter simpleFormatter = null;

	
	private LogDecompiler() 
    {
		try {
			String name = "decompiler.log";
			long tid = 0;
			
			log = Logger.getLogger("ghidra.app.decompiler");
			tid = Thread.currentThread().getId();
			
			// Creating handler
			fh = new FileHandler(String.format("%s.%d", name, tid));
			log.addHandler(fh);

			// Creating format
			simpleFormatter = new SimpleFormatter();
			fileHandler.setFormatter(simpleFormatter);
			
			// setting log-level
			log.setLevel(Level.ALL);
		}
		catch (IOException e){
			System.err.println("Create decompiler.log failed");
			System.err.println(e.toString());
		}
	}
	
	// static method to create instance of Singleton class 
    public static Logger getLogger() 
    { 
        if (single_instance == null) 
            single_instance = new LogDecompiler(); 
  
        return single_instance.log; 
	}	
}
