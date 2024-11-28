# WinSimpleInjector

### Installing steps:
* Git clone this repository `git clone https://github.com/Segward/WinSimpleInjector.git `
* Run the setup batch file ` .\setup `

### Usage:
* For 64-bit targets: ` injector <process name> <dll path> `
* For 32-bit targets: ` injector86 <process name> <dll path> `
* Your dll architecture must match the targets architecture

### Compiling
* I recommend using GCC for 32-bit and 64-bit processes. You can find my version of it WinGCC at `https://github.com/Segward/WinGCC`