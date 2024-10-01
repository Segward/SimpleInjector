@echo off
setlocal enabledelayedexpansion

echo --------------------------------------------

rem Query the user-specific Path variable from the registry and store it in userPath
for /f "tokens=2*" %%i in ('reg query "HKCU\Environment" /v Path 2^>nul') do (
    set "userPath=%%j"
)

rem Get the absolute path of a relative path
SET "RELATIVE_BIN_PATH=.\bin"
FOR %%i IN ("%RELATIVE_BIN_PATH%") DO SET "ABSOLUTE_BIN_PATH=%%~fi"

rem Add a new path to the userPath variable
set "unfilteredPath=;"
set "filteredPath=;"

rem Add absoluate path to the unfilteredPath variable
set "unfilteredPath=%unfilteredPath%;%ABSOLUTE_BIN_PATH%"

rem Filter out paths that are already in the userPath variable
for %%i in ("!unfilteredPath:;=";"!") do (
    set "isDuplicate=false"
    for %%j in ("!userPath:;=";"!") do (
        if "%%~i"=="%%~j" (
            if not "%%~i"=="" (
                echo %%~i is a duplicate
                set "isDuplicate=true"
            )
        )
    )
    if "!isDuplicate!"=="false" (
        if not "%%~i"=="" (
            echo %%~i is not a duplicate
            set "filteredPath=!filteredPath!;%%~i"
        )
    )
)

rem Add the filtered path to the userPath variable
set "userPath=%userPath%;%filteredPath%"

rem Set the new userPath variable in the registry
setx Path "%userPath%"

echo --------------------------------------------

rem End the local environment changes
endlocal
