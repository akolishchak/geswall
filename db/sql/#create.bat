
del ..\..\build\w32\release\geswall.dat
..\..\build\w32\release\sqlite ..\..\build\w32\release\geswall.dat<structure.sql

..\..\build\w32\release\gswapp.exe ..\..\app\db ..\..\build\w32\release\geswall.dat 4 >#appdb.log
type #appdb.log|find "Error"
del #appdb.log