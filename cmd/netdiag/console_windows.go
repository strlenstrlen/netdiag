//go:build windows

package main

import (
	"os"
	"syscall"
)

// Windows 10+ consoles render ANSI colors only once virtual-terminal
// processing is enabled for the output handle.
func init() {
	const enableVTProcessing = 0x0004
	k32 := syscall.NewLazyDLL("kernel32.dll")
	setMode := k32.NewProc("SetConsoleMode")
	h := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	if err := syscall.GetConsoleMode(h, &mode); err == nil {
		setMode.Call(uintptr(h), uintptr(mode|enableVTProcessing))
	}
}
