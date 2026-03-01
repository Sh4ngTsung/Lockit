@echo off
setlocal

chcp 65001 >nul

echo.
echo ----------------------------------------------------------------------
echo Starting LockIt program compilation and testing process.
echo ----------------------------------------------------------------------
echo.

where go >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [91mError: Go is not installed or not in PATH.[0m
    echo Install Go and try again.
    exit /b 1
)

echo Executing go mod tidy...
go mod tidy
if %errorlevel% neq 0 (
    echo.
    echo [91mError: go mod tidy failed. Check your dependencies.[0m
    exit /b 1
)
echo go mod tidy executed successfully.

echo Executing tests...
go test -v
if %errorlevel% neq 0 (
    echo.
    echo.
    echo [91mError: Tests failed. Build aborted.[0m
    exit /b 1
)
echo Tests executed successfully.

echo Current directory: %cd%

echo Compiling LockIt...
set "CGO_ENABLED=0"
go build -trimpath -ldflags "-s -w -extldflags '-static'" -o lockit.exe main.go > build.log 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [91mError: Compilation failed. Check the build.log for details.[0m
    type build.log
    exit /b 1
)
echo LockIt compiled successfully.

echo Checking if lockit.exe exists...
if not exist "lockit.exe" (
    echo Error: lockit.exe not found after compilation.
    echo Please check the build.log file for details.
    exit /b 1
)
echo lockit.exe found.

echo Creating C:\LockIt directory...
if not exist "C:\LockIt" mkdir "C:\LockIt"

echo Moving lockit.exe to C:\LockIt...
move /y lockit.exe "C:\LockIt\lockit.exe"
if %errorlevel% neq 0 (
    echo.
    echo [91mError: Failed to move lockit.exe file. Verify Administrator permissions.[0m
    exit /b 1
)
echo lockit.exe moved successfully.

echo Adding C:\LockIt to system PATH...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User'); if ($userPath -notmatch ';C:\\LockIt(;|$)' -and $userPath -notmatch '^C:\\LockIt(;|$)') { [Environment]::SetEnvironmentVariable('PATH', $userPath + ';C:\LockIt', 'User') }"
if %errorlevel% neq 0 (
    echo.
    echo [91mError: Failed to add C:\LockIt to PATH.[0m
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