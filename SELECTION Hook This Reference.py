#@author 
#@category _NEW_
#@keybinding ctrl h
#@menupath 
#@toolbar 

from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import ReferenceManager

from  _common import AddressLibrary
scriptName = "Hook  this function"

def GetFunctionCallOffsets(func,ref_address, ref_offset):
	entryPoint = func.getEntryPoint()
	instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
	i = 0
	for instr in instructions:
		# Check if the instruction is a function call
		if instr.getFlowType().isCall():
			# Get the address of the function being called
			ref = instr.getReferencesFrom()
			if(len(ref)>0):
				calledFunction = ref[0].getToAddress()
				offset = instr.getAddress().subtract(entryPoint)
				if(calledFunction == ref_address):
					if(offset == ref_offset):
						return i
					i += 1
	
	return None


class MyScript(GhidraScript):
	def run(self):
		library = AddressLibrary(currentProgram)

		if(not library.IsValid()):
			return
		
		func = getFunctionContaining(currentAddress)


		if func is not None:
			entryPoint = func.getEntryPoint()
			offset = currentAddress.subtract(entryPoint)

			instruction = getInstructionAt(currentAddress)
			ref = instruction.getOperandReferences(0)

			if(len(ref) > 0):
				ref_address = ref[0].getToAddress()

				ref_offset = currentAddress.subtract(entryPoint)

				index = GetFunctionCallOffsets(func, ref_address, ref_offset)

				library.TryPrintAddressExt(entryPoint, ref_address, ref_offset, index)
			else:
				library.PrintAddress(entryPoint, offset)

		else:
			print("address " + str(currentAddress) + " is not on a function")


script = MyScript()
script.run()

