@echo off
SETLOCAL

REM Specify the relative path you want to add to the PATH
SET "RELATIVE_BIN_PATH=.\injector.exe"

REM Get the absolute path from the relative path
FOR %%I IN ("%RELATIVE_BIN_PATH%") DO SET "ABSOLUTE_BIN_PATH=%%~fI"

REM Check if the directory is already in the PATH
echo %PATH% | find /I "%ABSOLUTE_BIN_PATH%" >nul

IF %ERRORLEVEL% NEQ 0 (
    REM If not, add it to the PATH
    SETX PATH "%PATH%;%ABSOLUTE_BIN_PATH%"
    echo Added %ABSOLUTE_BIN_PATH% to PATH.
) ELSE (
    echo %ABSOLUTE_BIN_PATH% is already in the PATH.
)

echo.

ENDLOCAL
