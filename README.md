# go-ThreadlessInject
Re-implementation of [CCob's C# ThreadlessInject](https://github.com/CCob/ThreadlessInject) technique in Golang. 

- Loader is the same
- Currently using high-level win API (Using indirect syscalls or whatev is on the TODO list - cc Acheron project)

### Why threadless injection ?
ThreadlessInject technique patches the first bytes of a Windows function in a remote process to call our shellcode loader. When the remote function is called, the loader patches back the function and runs our shellcode.

This technique allows shellcode injection without the need for an execution trigger primitive thus obfuscating the usual 3-step "Alloc-Write-Exec" injection timeline. Similar techniques already existed and were known as "function stomping" (as described in great blogpost by [KlezVirus](https://klezvirus.github.io/RedTeaming/AV_Evasion/FromInjectionToHijacking/]), however CCob's loader subtlely saves+recovers the stack so that 1) the hooked function still works properly and 2) only "one-time" hook meaning that further calls to the remote function do not run the shellcode anymore.

## Usage
```
export GOOS=windows && go build -o tinject.exe threadlessinject.go


.\tinject.exe -pid 1234 -fct NtOpenFile -dll ntdll.dll
```
