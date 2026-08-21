package sandbox

import "scbox/internal/third_party/goja"

var errnoForCode = map[string]int{
	"ENOENT":  -2,
	"EACCES":  -13,
	"EEXIST":  -17,
	"ENOTDIR": -20,
	"EISDIR":  -21,
	"EPERM":   -1,
}

var errMsgForCode = map[string]string{
	"ENOENT":           "no such file or directory",
	"EACCES":           "permission denied",
	"EEXIST":           "file already exists",
	"ENOTDIR":          "not a directory",
	"EISDIR":           "is a directory",
	"EPERM":            "operation not permitted",
	"MODULE_NOT_FOUND": "Cannot find module",
}

func (r *Runtime) nodeError(code, syscall, p string) goja.Value {
	msg := errMsgForCode[code]
	if msg == "" {
		msg = "error"
	}
	full := code + ": " + msg
	if syscall != "" {
		full += ", " + syscall
	}
	if p != "" {
		full += " '" + p + "'"
	}
	obj := r.errorObject("Error", full).ToObject(r.vm)
	set(obj, "code", code)
	if errno, ok := errnoForCode[code]; ok {
		set(obj, "errno", errno)
	}
	if syscall != "" {
		set(obj, "syscall", syscall)
	}
	if p != "" {
		set(obj, "path", p)
	}
	return obj
}

func (r *Runtime) errorObject(name, msg string) goja.Value {
	ctor := r.vm.Get(name)
	if fn, ok := goja.AssertFunction(ctor); ok {
		v, err := fn(goja.Undefined(), r.vm.ToValue(msg))
		if err == nil {
			return v
		}
	}
	fallback := r.obj()
	set(fallback, "name", name)
	set(fallback, "message", msg)
	return fallback
}
