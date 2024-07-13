#@author 
#@category _NEW_
#@keybinding ctrl alt b
#@menupath 
#@toolbar 

from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from  _common import AddressLibrary


scriptName = "Bookmark address library"
class MyScript(GhidraScript):
	def run(self):
		library = AddressLibrary(currentProgram)

		if(not library.IsValid()):
			return


		id = askInt(scriptName, "Please enter an address library id:")
		isEqual = library.getGameVersion() == "se"

		if(isEqual):
			address = library.GetMemory(id)
		else:
			matchId = library.GetIdForCurrentVersion(str(id))
			if(matchId == "-1"):
				print("Your id was not found in the version match, you will need to find it manually")
				return
			address = library.GetMemory(matchId)
			
		address = currentProgram.getAddressFactory().getAddress(address)
		
		goTo(address)

script = MyScript()
script.run()