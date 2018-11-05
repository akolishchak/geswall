
del ..\..\build\w32\release\geswall_s.dat
..\..\build\w32\release\sqlite ..\..\build\w32\release\geswall_s.dat<structure_server.sql

..\..\build\w32\release\gswapp.exe ..\..\app\dbserver ..\..\build\w32\release\geswall_s.dat 2 >#appdb.log
type #appdb.log|find "Error"
del #appdb.log