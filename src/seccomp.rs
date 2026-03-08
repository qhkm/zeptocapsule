//! seccomp-bpf filter for Hardened security profile.
//!
//! Installs a BPF syscall filter before execve. Only whitelisted syscalls
//! are allowed — everything else kills the process.

/// List of allowed syscall numbers for Hardened profile.
pub fn allowed_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_openat,
        libc::SYS_close,
        libc::SYS_stat,
        libc::SYS_fstat,
        libc::SYS_lstat,
        libc::SYS_newfstatat,
        libc::SYS_poll,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_ioctl,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        libc::SYS_select,
        libc::SYS_pselect6,
        libc::SYS_sched_yield,
        libc::SYS_mremap,
        libc::SYS_msync,
        libc::SYS_madvise,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getgroups,
        libc::SYS_socket,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_socketpair,
        libc::SYS_shutdown,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_kill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_uname,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_gettimeofday,
        libc::SYS_fcntl,
        libc::SYS_flock,
        libc::SYS_ftruncate,
        libc::SYS_fallocate,
        libc::SYS_getrandom,
        libc::SYS_memfd_create,
        libc::SYS_eventfd,
        libc::SYS_eventfd2,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_set_tid_address,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_sigaltstack,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_setaffinity,
        libc::SYS_getrlimit,
        libc::SYS_setrlimit,
        libc::SYS_prlimit64,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_mkdir,
        libc::SYS_mkdirat,
        libc::SYS_rmdir,
        libc::SYS_symlink,
        libc::SYS_symlinkat,
        libc::SYS_link,
        libc::SYS_linkat,
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_umask,
        libc::SYS_mlock,
        libc::SYS_munlock,
        libc::SYS_rseq,
    ]
}

/// Build a BPF filter program that allows whitelisted syscalls
/// and kills on all others.
pub fn build_seccomp_filter() -> Vec<libc::sock_filter> {
    let allowed = allowed_syscalls();
    let mut filter = Vec::new();

    // Load syscall number: BPF_LD | BPF_W | BPF_ABS, offset 0
    // (seccomp_data.nr)
    filter.push(bpf_stmt(0x20, 0)); // BPF_LD+BPF_W+BPF_ABS

    // For each allowed syscall: jump to ALLOW if match
    let num_allowed = allowed.len();
    for (i, &nr) in allowed.iter().enumerate() {
        let jt = (num_allowed - i) as u8; // jump forward to ALLOW
        filter.push(bpf_jump(0x15, nr as u32, jt, 0)); // BPF_JMP+BPF_JEQ+BPF_K
    }

    // Default: KILL_PROCESS
    filter.push(bpf_stmt(0x06, 0x80000000)); // BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS

    // ALLOW
    filter.push(bpf_stmt(0x06, 0x7fff0000)); // BPF_RET+BPF_K, SECCOMP_RET_ALLOW

    filter
}

/// Install the seccomp filter. Must be called after PR_SET_NO_NEW_PRIVS
/// and before execve.
pub fn install_seccomp_filter() -> Result<(), String> {
    let filter = build_seccomp_filter();

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };

    let ret =
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1i64, // SECCOMP_SET_MODE_FILTER
            0i64,
            &prog as *const libc::sock_fprog as i64,
        )
    };
    if ret != 0 {
        return Err(format!(
            "seccomp install failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_filter_has_expected_size() {
        let filter = build_seccomp_filter();
        // header (1) + allowed syscalls + KILL (1) + ALLOW (1)
        assert!(
            filter.len() > 10,
            "filter too small: {} instructions",
            filter.len()
        );
    }

    #[test]
    fn seccomp_allowed_syscalls_are_reasonable() {
        let allowed = allowed_syscalls();
        assert!(allowed.contains(&libc::SYS_read));
        assert!(allowed.contains(&libc::SYS_write));
        assert!(allowed.contains(&libc::SYS_openat));
        assert!(allowed.contains(&libc::SYS_close));
        assert!(allowed.contains(&libc::SYS_mmap));
        assert!(allowed.contains(&libc::SYS_execve));
        // Dangerous syscalls must NOT be in the list
        assert!(!allowed.contains(&libc::SYS_reboot));
        assert!(!allowed.contains(&libc::SYS_kexec_load));
        assert!(!allowed.contains(&libc::SYS_init_module));
    }
}
