#TODO write a description for this script
#@author
#@category _NEW_
#@keybinding
#@menupath
#@toolbar
import os
from ghidra.program.model.symbol import SourceType
from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import ReferenceManager

from  _common import AddressLibrary

symbol_table = currentProgram.getSymbolTable()

script_dir = os.path.dirname(os.path.realpath(__file__))

scriptName = "Rename All Known Code Units"

def GetFunctionCallOffsets(library, address):
    func = getFunctionAt(address)
    result = []
    if func is not None:
        entryPoint = func.getEntryPoint()
        offset = address.subtract(entryPoint)
        epid = library.GetID(entryPoint)
        if(epid == None):
            return result

        instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
        for instr in instructions:
            # Check if the instruction is a function call
            if instr.getFlowType().isCall():
                # Get the address of the function being called
                ref = instr.getReferencesFrom()
                if(len(ref)>0):
                    calledFunction = ref[0].getToAddress()
                    offset = instr.getAddress().subtract(entryPoint)

                    cfid = library.GetID(calledFunction)

                    if(cfid == None):
                        continue
    
                    result.append(epid+";"+cfid+";"+hex(offset).rstrip('L')+"\n")
    return result


class MyScript(GhidraScript):
    def run(self):
        library = AddressLibrary(currentProgram)

        if(not library.IsValid()):
            return

        with open(script_dir+'\\misc\\function-call-offsets-'+library.game_version+'.csv', 'w') as f:
            for id in library.GetAllIds():
                addressStr = library.GetMemory(id)
                if(addressStr == "-1"):
                    continue

                address = currentProgram.getAddressFactory().getAddress(addressStr)
                functionCalls = GetFunctionCallOffsets(library, address)

                for functionCall in functionCalls:
                    f.write(functionCall)

script = MyScript()
script.run()
