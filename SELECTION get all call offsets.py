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

			instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
			for instr in instructions:
				# Check if the instruction is a function call
				if instr.getFlowType().isCall():
					# Get the address of the function being called
					ref = instr.getReferencesFrom()
					if(len(ref)>0):
						calledFunction = ref[0].getToAddress()

						data = library.GetMemoryData(calledFunction)
						if data == "-1":
							try:
								instruction = getInstructionAt(calledFunction)
								ref_address = instruction.getOperandReferences(0)[0].getToAddress()
								data = library.GetMemoryData(ref_address)
							except:
								print("definition not found")

						if data:
							if(data == "-1"):
								print("definition not found")
							else:
								print(data["definition"])

						if not library.PrintAddressLibraryIds(calledFunction):
							try:
								instruction = getInstructionAt(calledFunction)
								ref_address = instruction.getOperandReferences(0)[0].getToAddress()
								library.PrintAddressLibraryIds(ref_address)
							except:
								print("Failed to get the reference")
								print("This might not be a known function")
								print("Otherwise, if you are in a function, you could try going to the definition of the item")

		else:
			print("address " + str(currentAddress) + " is not on a function")


script = MyScript()
script.run()

