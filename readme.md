### General
For the scripts to work, the address library offsets must be in the database, if you are not using 1.6.1170.0 or 1.5.97.0 you will need to add them to the database [Here](#adding-your-skyrim-version-to-the-database) is how you do it 


### Changelog

To use it now is necessary to extract data.7z on the root folder, i do not what to add that many files to the source control

![image](https://github.com/user-attachments/assets/fbed5d60-f05f-45b3-860d-06a415ea0fcf)

Now it is blazing fast, however it reqquires you to extract a zip file with 3.265.867 tiny files

The hook all references to that address were removed, i don't think that should be done.

The hook this reference now gives the offset for the other version of skyrim, it is a heuristic, but is a pretty good heuristic

![image](https://github.com/user-attachments/assets/b9689912-0b59-40b5-bc00-47ecd4f08b37)


### GLOBAL Rename All Known Functions.py

This script will rename all known functions that are in the definition database
You will be asked if you want to delete existing symbols. It is highly suggested that you say no; however, if you do so, functions that you have already renamed will not be renamed

![image](https://github.com/Thiago099/ghidra_scripts/assets/66787043/4f448293-4c7b-4e2a-938c-d95104101e6f)

### GLOBAL Bookmark An Address.py

This script will ask you for an address library ID, and it will bookmark the address of that ID

![image](https://github.com/Thiago099/ghidra_scripts/assets/66787043/d7757f3b-9f59-45e9-b450-6d93e202896e)


You can use IDs from SE on AE and vice versa for as long as they are in the database, you must answer this prompt correctly

If you however provide the right id to your game version it only needs to be on the id database, instead of both the id and the match database

![image](https://github.com/Thiago099/ghidra_scripts/assets/66787043/819ae529-7c4d-405e-a03f-e60946c38ba2)

### SELECTION Get Info.py

This script will print basic information about the selected address, if found on the database

![image](https://github.com/Thiago099/ghidra_scripts/assets/66787043/b510a5b1-728e-43a2-b02c-367232509534)

### SELECTION Get Address Library Ids.py

This script will return both the AE and SE address library IDs of the selected code unit, if they are in the database.

Example of output

![image](https://github.com/Thiago099/ghidra_scripts/assets/66787043/367148a6-fd27-4cde-81c6-043f54ceb682)

### SELECTION Hook This Reference.py

If the selected address is in a function, it will display the id of this function on the Address Library and the offset of where this address is in that function

![image](https://github.com/user-attachments/assets/1b621c33-3f53-4175-84cd-c475cd680efc)

### Adding your skyrim version to the database:

You can generate a dump of your specific version of skyrim by adding this code to any SKSE plugin. You can get the header file [here](https://www.nexusmods.com/skyrimspecialedition/mods/32444?tab=files)

```c++


#include "versiondb.h"

bool DumpSpecificVersion()
{
VersionDb db;

// Try to load database of version 1.5.62.0 regardless of running executable version.
if (!db.Load(1, 5, 62, 0))
{
_FATALERROR("Failed to load database for 1.5.62.0!");
return false;
}

// Write out a file called offsets-1.5.62.0.txt where each line is the ID and offset.
db.Dump("offsets-1.5.62.0.txt");
_MESSAGE("Dumped offsets for 1.5.62.0");
return true;
}
```

After you do that, you can rename and put the file you generated (it will be on your skyrim root folder) in the data folder of this project

it needs to follow this naming convetion

offsets-`<ae-or-se>`-`<full-game-version>`.txt

Finally, you can run the first cell on the ipynb file to update the database used by these scripts
