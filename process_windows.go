// +build windows

package ps

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Windows API functions
var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = modKernel32.NewProc("Process32FirstW")
	procProcess32Next            = modKernel32.NewProc("Process32NextW")
	procOpen  					 = modKernel32.NewProc("OpenProcess")
	procQueryImagePath = modKernel32.NewProc("QueryFullProcessImageNameA")


)

// Some constants from the Windows API
const (
	ERROR_NO_MORE_FILES = 0x12
	MAX_PATH            = 260
	PROCESS_ALL_ACCESS = 0x1F0FFF
	PROCESS_NAME_WIN32FORMAT = 0
	PROCESS_NAME_NATIVE = 1
)
type ProcessAddress uintptr

// PROCESSENTRY32 is the Windows API structure that contains a process's
// information.
type PROCESSENTRY32 struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriorityClassBase int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

// WindowsProcess is an implementation of Process for Windows.
type WindowsProcess struct {
	pid  int
	ppid int
	exe  string
}

func (p *WindowsProcess) Pid() int {
	return p.pid
}

func (p *WindowsProcess) PPid() int {
	return p.ppid
}

func (p *WindowsProcess) Executable() string {
	return p.exe
}
func (p *WindowsProcess) GetProcessData() ProcessData {
	//fmt.Printf("calling get processdata...pid is %d\n",p.pid)
	handle:=openProcessHandle(p.pid)
	defer CloseHandle(handle)


	processPathTarget := make([]byte, 500)
	var numBytesRead uintptr = 500
	//fmt.Printf("got handle for process: %d\n", handle)

	ret, _, _ := procQueryImagePath.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&processPathTarget[0])),
		uintptr(unsafe.Pointer(&numBytesRead)),
		)
	if ret == 0 {
		return ProcessData{"",0,false, "Error retrieving process info from kernel"}
	} else {
		//fmt.Printf("success: %v, %d",string(data),numBytesRead)
		//return fmt.Sprintf("success: %v, %d\n",string(processPathTarget[:numBytesRead]),numBytesRead)
		return ProcessData{string(processPathTarget[:numBytesRead]), int(numBytesRead), true,""}
	}
}

func newWindowsProcess(e *PROCESSENTRY32) *WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return &WindowsProcess{
		pid:  int(e.ProcessID),
		ppid: int(e.ParentProcessID),
		exe:  syscall.UTF16ToString(e.ExeFile[:end]),
	}
}
func openProcessHandle(processId int) uintptr {
	//open the process we are examining
	handle, _, _ := procOpen.Call(ptr(PROCESS_ALL_ACCESS), ptr(true), ptr(processId	))
	return handle
}
func CloseHandle(object uintptr) bool {
	ret, _, _ := procCloseHandle.Call(
		uintptr(object))
	return ret != 0
}

func ptr(val interface{}) uintptr {
	switch val.(type) {
	case string:
		return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(val.(string))))
	case int:
		return uintptr(val.(int))
	default:
		return uintptr(0)
	}
}
func findProcess(pid int) (Process, error) {
	ps, err := processes()
	if err != nil {
		return nil, err
	}

	for _, p := range ps {
		if p.Pid() == pid {
			return p, nil
		}
	}

	return nil, nil
}

func processes() ([]Process, error) {
	handle, _, _ := procCreateToolhelp32Snapshot.Call(
		0x00000002,
		0)
	if handle < 0 {
		return nil, syscall.GetLastError()
	}
	defer procCloseHandle.Call(handle)

	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := procProcess32First.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Error retrieving process info.")
	}

	results := make([]Process, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		ret, _, _ := procProcess32Next.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return results, nil
}
