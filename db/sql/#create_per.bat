
del ..\..\build\w32\release\geswall_per.dat
..\..\build\w32\release\sqlite ..\..\build\w32\release\geswall_per.dat<structure.sql

..\..\build\w32\release\gswapp.exe ..\..\app\db ..\..\build\w32\release\geswall_per.dat 1 >#appdb.log
type #appdb.log|find "Error"
del #appdb.log