# go-ThreadlessInject
Re-implementation of [CCob's C# ThreadlessInject](https://github.com/CCob/ThreadlessInject) technique in Golang. 

- Loader is the same
- Currently using high-level win API (Using indirect syscalls is on the TODO list - [Acheron](https://github.com/f1zm0/acheron))

![](./images/animation.gif)
### Why threadless injection ?
ThreadlessInject technique patches the first bytes of a Windows function in a remote process to call our shellcode loader. When the remote function is called, the loader patches back the function and runs our shellcode.

This technique allows shellcode injection without the need for an execution trigger primitive thus obfuscating the usual 3-step "Alloc-Write-Exec" injection timeline. Similar techniques already existed and were known as "function stomping" (as described in great blogpost by [KlezVirus](https://github.com/klezVirus/klezVirus.github.io/tree/master/RedTeaming/AV_Evasion/FromInjectionToHijacking)), however CCob's loader subtlely saves+recovers the registers and stack state so that 1) the hooked function still works properly and 2) only "one-time" hook meaning that further calls to the remote function do not run the shellcode anymore.

## Usage
```
export GOOS=windows && go build -o tinject.exe threadlessinject.go

# Example usage 
.\tinject.exe -pid 1234 -fct NtOpenFile -dll ntdll.dll
```

### Known issues
- If the program loops and doens't find a memory hole : turns out that if your golang installation is not in English, some error messages are different and break the allocation checks (just remove the "The operation completed successfully." checks......)
