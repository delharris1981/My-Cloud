package vfs

import "syscall"

// syscallEXDEV is the cross-device-link error. Comparing against the syscall
// constant keeps the check exact on platforms where os.LinkError wraps it.
const syscallEXDEV = syscall.EXDEV
