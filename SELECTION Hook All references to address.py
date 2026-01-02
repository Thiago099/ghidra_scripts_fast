#@author 
#@category _NEW_
#@keybinding ctrl h
#@menupath 
#@toolbar 

from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import ReferenceManager

from  _common import AddressLibrary, ParseInstruction
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
		

		refs = currentProgram.referenceManager.getReferencesTo(currentAddress)

		if not refs.hasNext():
			instruction = getInstructionAt(currentAddress)
			ref_address = instruction.getOperandReferences(0)[0].getToAddress()
			refs = currentProgram.referenceManager.getReferencesTo(ref_address)

		for ref in refs:

			address = ref.getFromAddress()

			func = getFunctionContaining(address)


			if func is not None:
				entryPoint = func.getEntryPoint()
				offset = address.subtract(entryPoint)

				instruction = getInstructionAt(address)
				ref = instruction.getOperandReferences(0)

				(kind, size) = ParseInstruction(instruction)


				if(len(ref) > 0):
					ref_address = ref[0].getToAddress()

					ref_offset = address.subtract(entryPoint)

					index = GetFunctionCallOffsets(func, ref_address, ref_offset)

					library.TryPrintAddressExt(entryPoint, ref_address, ref_offset, index, kind, size)
				else:
					library.PrintAddress(entryPoint, offset)

			else:
				print("address " + str(address) + " is not on a function")


script = MyScript()
script.run()

