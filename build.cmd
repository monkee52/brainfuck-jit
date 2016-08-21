@ECHO OFF

IF EXIST "out" RMDIR /S /Q "out"

MKDIR "out"
MKDIR "out\bin"

IF EXIST "programs" XCOPY "programs\*.*" "out\bin\programs" /E /I

cl.exe /O2 /c "jit.c" /Fo"out\jit.obj"
rc.exe /fo"out\jit.res" "jit.rc"
link.exe /SUBSYSTEM:CONSOLE /RELEASE /OUT:"out\bin\jit.exe" /DEBUG /PDB:"out\jit.pdb" "out\jit.obj" "out\jit.res"
