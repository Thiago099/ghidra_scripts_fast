


import os
import pickle

script_dir = os.path.dirname(os.path.realpath(__file__))


def load_item(*base_path):
    path = os.path.join(script_dir, "data", *base_path)+".pickle"
    if(not os.path.isfile(path)):
        return None
    
    with open(path, 'rb') as f:
        return pickle.load(f)


pair = {"ae":"se","se":"ae"}

def MemoryToAddressLibrary(version, input):
    input = "0x"+str(input)[2:].lstrip('0')
    output = load_item("offsets", version, "skyrim-to-address", input)
    if(output == None):
        print("address "+input+" not found on address library")
        return 0
    return output

def MemoryToAddressLibrarySilent(version, input):
    input = "0x"+str(input)[2:].lstrip('0')
    output = load_item("offsets", version, "skyrim-to-address", input)
    if output== None:
        return "-1"
    return output

def AddressLibraryToMemory(version, input):
    output = load_item("offsets", version, "address-to-skyrim", input)
    if output == None:
        print("address "+str(input)+" not found on address library")
        return "-1"
    raw_address = int(output,16)
    offset = 0x140000000
    return hex(offset+raw_address)

def GetMatchID(game_version, input):
    output = load_item("addresses_match", game_version, input)
    if output == None:
        print("failed to get the match address for input: "+input)
        return "-1"
    return output


def GetAddressData(game_version,version, input):
    if(game_version == "ae"):
        input = GetMatchID("ae", input)
    output = load_item("definition", input)
    if(output == None):
        return "-1"
    return output

def GetAllIds(game_version):
    path = os.path.join(script_dir, "data", "definition")
    files = os.listdir(path)
    defined_ids = []
    for file in files:
        filename, extension = os.path.splitext(file)
        defined_ids.append(filename)
    if(game_version == "ae"):
        input =  [item for item in [GetMatchID("se", item) for item in list(defined_ids)] if item != "-1"]
    else:
        input = list(defined_ids)
    return input

class AddressLibrary:
    def __init__(self, currentProgram):
        metadata = currentProgram.getMetadata()
        self.version = metadata["PE Property[ProductVersion]"]
        output = load_item("offsets", self.version, "game-version")
        if(output != None):
            self.game_version = output
        else:
            self.game_version = None
            print("version "+ self.version +" was not on the database, you need to generate the files")

    def IsValid(self):
        return self.game_version != None

    def GetCurrentVersionId(self,target_version, id):
        if(target_version == self.game_version):
            return id
        return GetMatchID(self.game_version, id)
    
    def GetIdForCurrentVersion(self, id):
        return GetMatchID(pair[self.game_version], id)
    
    def getGameVersion(self):
        return self.game_version
    def getExactVersion(self):
        return self.version
    def GetAllIds(self):
        return GetAllIds(self.game_version)
    
    def GetAddressData(self, id):
        return GetAddressData(self.game_version, self.version, id)
    def GetMemoryData(self, address):
        id = str(MemoryToAddressLibrarySilent(self.version, str(address)))
        if id == "-1":
            return "-1"
        return GetAddressData(self.game_version, self.version, id)
    
    def PrintAddress(self, entryPoint, offset):
        oid = str(MemoryToAddressLibrary(self.version,entryPoint))
        mid = GetMatchID(self.game_version, oid)
        if(self.game_version == "ae"):
            print("__ ADDRESS AND OFFSET __")
            if(mid != "-1"):
                print("SE ID: "+ mid)
            print("AE ID: "+ oid + " AE Offset: "+hex(offset).rstrip('L'))
        else:
            print("__ ADDRESS AND OFFSET __")
            print("SE ID: "+ oid + " SE Offset: "+hex(offset).rstrip('L'))
            if(mid != "-1"):
                print("AE ID: "+ mid)

    def GetGameVersion(self):
        return self.game_version.upper()

    def GetMemory(self, address):
        return AddressLibraryToMemory(self.version, address).rstrip('L')
    
    def PrintAddressLibraryIds(self, address):
        id = str(MemoryToAddressLibrarySilent(self.version, str(address)))
        if id == "-1":
            return False
        pair = GetMatchID(self.game_version, id)
        if(str(pair)=="-1"):
            return False

        if(self.game_version == "ae"):
            print("SE: "+str(pair))
            print("AE: "+str(id))
        else:
            print("SE: "+str(id))
            print("AE: "+str(pair))

        return True



