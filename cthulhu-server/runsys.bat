@echo off
rem 启动第一个可执行文件
start "" "cthulhu.exe" "run" "-s"
rem 启动第二个可执行文件
start "" "mitm.exe"

rem 等待程序启动
ping -n 5 127.0.0.1 >nul

rem 获取第一个程序的 PID
for /f "tokens=2 delims=," %%a in ('tasklist /nh /fi "imagename eq cthulhu.exe" /fo csv') do set "pid1=%%~a"
rem 获取第二个程序的 PID
for /f "tokens=2 delims=," %%a in ('tasklist /nh /fi "imagename eq mitm.exe" /fo csv') do set "pid2=%%~a"

rem 等待用户输入，直到用户关闭窗口
choice /c:q /n /m "Press Q to quit and close both programs: "
if errorlevel 1 (
    rem 终止第一个程序
    taskkill /f /pid %pid1%
    rem 终止第二个程序
    taskkill /f /pid %pid2%
)