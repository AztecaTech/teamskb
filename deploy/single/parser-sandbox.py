"""Fail closed: the parser can create Unix sockets, but no network sockets."""
import ctypes
import errno
import resource
import runpy
import socket


def restrict():
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise RuntimeError("parser privilege restriction failed")
    seccomp = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int

    class Comparison(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("a", ctypes.c_uint64), ("b", ctypes.c_uint64)]

    seccomp.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                             ctypes.c_int, ctypes.c_uint, ctypes.POINTER(Comparison)]
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    context = seccomp.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError("parser sandbox allocation failed")
    try:
        # SCMP_CMP_NE: deny every socket family except AF_UNIX, inherited by children.
        comparison = Comparison(0, 1, socket.AF_UNIX, 0)
        syscall = seccomp.seccomp_syscall_resolve_name(b"socket")
        if syscall < 0 or seccomp.seccomp_rule_add_array(context, 0x50000 | errno.EPERM,
                                                       syscall, 1, ctypes.byref(comparison)) != 0:
            raise RuntimeError("parser socket rule failed")
        if seccomp.seccomp_load(context) != 0:
            raise RuntimeError("parser sandbox activation failed")
    finally:
        seccomp.seccomp_release(context)


if __name__ == "__main__":
    restrict()
    runpy.run_path("/opt/iqkb/parser.py", run_name="__main__")
