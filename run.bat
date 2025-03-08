@echo off
setlocal

chcp 65001 >nul

echo.
echo ----------------------------------------------------------------------
echo Starting LockIt program compilation and testing process.
echo ----------------------------------------------------------------------
echo.

REM Check if Go is installed
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [91mError: Go is not installed or not in PATH.[0m
    echo Install Go and try again.
    exit /b 1
)

REM Execute go mod tidy to ensure dependencies are installed
echo Executing go mod tidy...
go mod tidy
if %errorlevel% neq 0 (
    echo.
    echo [91mError: go mod tidy failed. Check your dependencies.[0m
    exit /b 1
)
echo go mod tidy executed successfully.

REM Execute tests
echo Executing tests...
go test -v
if %errorlevel% neq 0 (
    echo.
    echo.
    echo [91mError: Tests failed. Build aborted.[0m
    exit /b 1
)
echo Tests executed successfully.

REM Check the current directory before building
echo Current directory: %cd%

REM Compile the project and capture the output
echo Compiling LockIt...
set CGO_ENABLED=0 && go build -trimpath -ldflags "-s -w -extldflags \"-static\"" -o lockit.exe main.go > build.log 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [91mError: Compilation failed. Check the build.log for details.[0m
    type build.log
    exit /b 1
)
echo LockIt compiled successfully.

REM Check if lockit.exe exists after compilation
echo Checking if lockit.exe exists...
if not exist "lockit.exe" (
    echo Error: lockit.exe not found after compilation.
    echo Please check the build.log file for details.
    exit /b 1
)
echo lockit.exe found.

REM Create the C:\LockIt directory if it doesn't exist
echo Creating C:\LockIt directory...
if not exist "C:\LockIt" mkdir "C:\LockIt"

REM Move lockit.exe to the C:\LockIt directory
echo Moving lockit.exe to C:\LockIt...
move /y lockit.exe "C:\LockIt\lockit.exe"
if %errorlevel% neq 0 (
    echo.
    echo [91mError: Failed to move lockit.exe file.[0m
    exit /b 1
)
echo lockit.exe moved successfully.

REM Add C:\LockIt to system PATH without truncating
for /f "tokens=2 delims==" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path ^| findstr Path') do set OLD_PATH=%%A
echo Adding C:\LockIt to system PATH...
setx PATH "%OLD_PATH%;C:\LockIt"
if %errorlevel% neq 0 (
    echo.
    echo [91mError: Failed to add C:\LockIt to PATH.[0m
    echo Run this script as administrator.
    exit /b 1
)
echo C:\LockIt added to PATH successfully.

echo.
echo ----------------------------------------------------------------------
echo [92mBuild successful! lockit.exe has been moved to C:\LockIt and is available in your PATH.[0m
echo You can run it directly from CMD or PowerShell.
echo ----------------------------------------------------------------------
echo.

pause
endlocal
