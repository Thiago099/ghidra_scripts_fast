


import os
import pickle

script_dir = os.path.dirname(os.path.realpath(__file__))


def load_item(*base_path):
    path = os.path.join(script_dir, "data", *[str(i)for i in base_path])+".pickle"

    if(not os.path.isfile(path)):
        return None
    
    with open(path, 'rb') as f:
        return pickle.load(f)


pair = {"ae":"se","se":"ae"}

def MemoryToAddressLibrary(version, input):
    input = "0x"+str(input)[2:].lstrip('0')
    output = load_item("offsets", version, "skyrim-to-address", input)
    if(output == None):
        # print("address "+input+" not found on address library")
        return "-1"
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
        # print("address "+str(input)+" not found on address library")
        return "-1"
    raw_address = int(output,16)
    offset = 0x140000000
    return hex(offset+raw_address)

def GetFunctionCallOffsets(game_version, id, cid, index):
    output = load_item("function_call_offsets", game_version, id)
    if output == None:
        return "-1"
    if cid in output:
        if(index < len(output[cid])):
            return output[cid][index]
    return "-1"


def GetMatchID(game_version, input):
    output = load_item("addresses_match", game_version, input)
    if output == None:
        # print("failed to get the match address for input: "+input)
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
    i = 0
    if(game_version == "ae"):
        for item in defined_ids:
            if(i % 1000 == 0):
                print(str(i)+" / "+str(len(defined_ids)))
            match_id = GetMatchID("se", item)
            # check if the match id is not "-1"
            if match_id != "-1":
                yield match_id
            i+=1
    else:
        for item in defined_ids:
            if(i % 1000 == 0):
                print(str(i)+" / "+str(len(defined_ids)))
            yield item
            i+=1

def GetPrettyNull(input):
    if(input == "-1"):
        return "Not Found"
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
    

    def TryPrintAddressExt(self, entryPoint, ref_address, ref_offset, index):
        fid = str(MemoryToAddressLibrary(self.version, entryPoint))
        cid = str(MemoryToAddressLibrary(self.version, ref_address))
        ofid = GetMatchID(self.game_version, fid)
        ocid = GetMatchID(self.game_version, cid)
        ooffset = GetFunctionCallOffsets(pair[self.game_version],ofid, ocid, index)
        

        if(self.game_version == "ae"):
            print("__ ADDRESS AND OFFSET __")
            print("SE ID: "+ GetPrettyNull(ofid)+ " SE Offset: " + GetPrettyNull(ooffset) + " (Heuristic)")
            print("AE ID: "+ fid + " AE Offset: " + hex(ref_offset).rstrip('L'))
        else:
            print("__ ADDRESS AND OFFSET __")
            print("SE ID: "+ fid + " SE Offset: " + hex(ref_offset).rstrip('L'))
            print("AE ID: "+ GetPrettyNull(ofid) + " AE Offset: "+GetPrettyNull(ooffset) + " (Heuristic)")


    def PrintAddress(self, entryPoint, offset):
        oid = str(MemoryToAddressLibrary(self.version,entryPoint))
        mid = GetMatchID(self.game_version, oid)
        if(self.game_version == "ae"):
            print("__ ADDRESS AND OFFSET __")
            print("SE ID: "+ GetPrettyNull(mid))
            print("AE ID: "+ oid + " AE Offset: "+hex(offset).rstrip('L'))
        else:
            print("__ ADDRESS AND OFFSET __")
            print("SE ID: "+ oid + " SE Offset: "+hex(offset).rstrip('L'))
            print("AE ID: "+ GetPrettyNull(mid))

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
    
    def GetID(self, address):
        id = str(MemoryToAddressLibrarySilent(self.version, str(address)))
        if id == "-1":
            return None
        return str(id)
        





