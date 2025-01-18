#@author 
#@category _NEW_
#@keybinding ctrl alt b
#@menupath 
#@toolbar 

from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from  _common import AddressLibrary


scriptName = "Bookmark address library"


scriptName = "Bookmark address library"
class MyScript(GhidraScript):
	def run(self):
		offset = askInt(scriptName, "Please enter the offset")
		goTo(currentAddress.add(offset))

script = MyScript()
script.run()
