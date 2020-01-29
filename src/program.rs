use goblin::Object;
use nix::libc::user_regs_struct;
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;

use crate::error::*;
use crate::maps::{Entry, MapReader};
use nix::sys::uio::{process_vm_readv, process_vm_writev, IoVec, RemoteIoVec};
use std::io::Read;
use std::os::raw::{c_long, c_void};
use std::path::Path;

pub struct Program {
    pid: Pid,
    maps: Vec<Entry>,
}

impl Program {
    pub fn ptrace(pid: Pid) -> Result<Program> {
        ptrace::attach(pid)?;
        waitpid(pid, None)?;

        let maps = MapReader::from_pid(pid)?.collect();
        Ok(Program { pid, maps })
    }

    pub fn cont(&mut self) -> Result<()> {
        ptrace::cont(self.pid, None)?;

        Ok(())
    }

    // Must have been traced & paused
    fn protect(&self) -> Result<ProgramContextGuard> {
        Ok(ProgramContextGuard::protect(self.pid)?)
    }

    pub fn dlsym(&self, handle: u64, func_name: &str) -> Result<*mut c_void> {
        let func_name = self.alloc_str(func_name)?;

        let libc_entry = self.select_lib(Self::generate_name_lib_selector("/libc-"))?;
        let dlsym_address = self.get_func_in_lib("__libc_dlsym", libc_entry)?;
        let guard = self.protect()?;

        let mut regs = guard.regs();
        regs.rax = dlsym_address as u64; // dlsym
        regs.rdi = handle; // handle
        regs.rsi = func_name as u64; // symbol

        guard.set_regs(regs)?;
        Ok(guard.call_and_int()? as *mut c_void)
    }

    pub fn generate_name_lib_selector(name: &str) -> impl FnMut(&&Entry) -> bool + '_ {
        move |entry| {
            entry.path.contains(name)
                && entry.privilege.contains("r")
                && entry.privilege.contains("xp")
        }
    }

    pub fn dlopen<P: AsRef<Path>>(&self, path: P) -> Result<u64> {
        let path = self.alloc_str(path.as_ref().to_str()?)?;

        let libc_entry = self.select_lib(Self::generate_name_lib_selector("/libc-"))?;
        let dlopen_address = self.get_func_in_lib("__libc_dlopen_mode", libc_entry)?;
        let guard = self.protect()?;

        let mut regs = guard.regs();
        regs.rax = dlopen_address as u64; // dlopen
        regs.rdi = path as u64; // filename
        regs.rsi = 1; // RTLD_LAZY

        guard.set_regs(regs)?;
        Ok(guard.call_and_int()?)
    }

    fn get_lib_buffer(&self, lib_entry: &Entry) -> Result<Vec<u8>> {
        if lib_entry.path.contains("/") {
            let mut lib_file = std::fs::File::open(lib_entry.path.clone())?;
            let mut lib_buffer = Vec::new();
            lib_file.read_to_end(&mut lib_buffer).unwrap();

            Ok(lib_buffer)
        } else {
            let size = (lib_entry.end_addr - lib_entry.start_addr) as usize;

            let mut lib_buffer: Vec<u8> = Vec::with_capacity(size);
            lib_buffer.resize(size, 0);
            self.read_slice(
                lib_buffer.as_mut_slice(),
                lib_entry.start_addr as *mut c_void,
            )?;

            Ok(lib_buffer)
        }
    }

    pub fn select_lib<F>(&self, filter: F) -> Option<&Entry>
    where
        F: FnMut(&&Entry) -> bool,
    {
        self.maps.iter().filter(filter).nth(0)
    }

    pub fn get_func_in_lib(&self, func_name: &str, lib_entry: &Entry) -> Result<*mut c_void> {
        let lib_buffer = Self::get_lib_buffer(self, lib_entry)?;

        match Object::parse(&lib_buffer).unwrap() {
            Object::Elf(elf) => {
                for dynsym in elf.dynsyms.iter() {
                    let name = elf.dynstrtab.get(dynsym.st_name)?;
                    match name {
                        Ok(name) => {
                            if name == func_name {
                                let offset = dynsym.st_value as usize;

                                let func_address =
                                    lib_entry.start_addr + (offset as u64) - lib_entry.padding_size;

                                return Ok(func_address as *mut c_void);
                            }
                        }
                        _ => {}
                    }
                }

                Err(Error::from("cannot find library or function"))
            }
            _ => Err(Error::from("lib is not an ELF file")),
        }
    }

    pub fn alloc_str(&self, s: &str) -> Result<*mut c_void> {
        let mut buf = s.to_owned().into_bytes();
        buf.resize(s.len() + 1, 0);

        Ok(self.alloc_slice(&buf)?)
    }

    pub fn alloc_slice(&self, slice: &[u8]) -> Result<*mut c_void> {
        let addr = self.mmap(slice.len(), 0)?;

        self.write_slice(slice, addr)?;

        Ok(addr)
    }

    pub fn write_slice(&self, slice: &[u8], target: *mut c_void) -> Result<()> {
        if slice.len() > 512 {
            let local_iov = IoVec::from_slice(slice);
            let remote_iov = RemoteIoVec {
                base: target as usize,
                len: slice.len(),
            };
            process_vm_writev(self.pid, &[local_iov], &[remote_iov])?;
        } else {
            for (index, byte) in slice.iter().enumerate() {
                ptrace::write(self.pid, unsafe { target.add(index) }, *byte as *mut c_void)
                    .unwrap();
            }
        }

        Ok(())
    }

    fn read_slice(&self, slice: &mut [u8], start_addr: *mut c_void) -> Result<()> {
        let len = slice.len();

        let local_iov = IoVec::from_mut_slice(slice);
        let remote_iov = RemoteIoVec {
            base: start_addr as usize,
            len,
        };

        process_vm_readv(self.pid, &[local_iov], &[remote_iov])?;
        Ok(())
    }

    pub fn mmap(&self, length: usize, fd: u64) -> Result<*mut c_void> {
        let guard = self.protect()?;

        let mut regs = guard.regs();
        regs.rax = 9; // mmap
        regs.rdi = 0; // addr
        regs.rsi = length as u64; // length
        regs.rdx = 7; // prot
        regs.r10 = 0x22; // flags
        regs.r8 = fd; // fd
        regs.r9 = 0; // offset

        guard.set_regs(regs)?;
        Ok(guard.syscall()?)
    }

    pub fn hard_replace_fun(&self, orig_fun: *mut c_void, new_fun: *mut c_void) -> Result<()> {
        let mut instructions: Vec<u8> = vec![0; 16];
        instructions[0] = 0x48;
        instructions[1] = 0xb8;
        unsafe {
            *(&mut instructions[2] as *mut u8 as *mut u64) = new_fun as u64;
        }
        instructions[10] = 0xff;
        instructions[11] = 0xe0;

        let first_part = unsafe { *(&instructions[0] as *const u8 as *const u64) };
        let second_part = unsafe { *(&instructions[8] as *const u8 as *const u64) };
        ptrace::write(self.pid, orig_fun, first_part as *mut c_void)?;
        ptrace::write(
            self.pid,
            unsafe { orig_fun.add(8) },
            second_part as *mut c_void,
        )?;

        Ok(())
    }
}

struct ProgramContextGuard {
    backup_regs: user_regs_struct,
    backup_code: c_long,
    pid: Pid,
}

impl ProgramContextGuard {
    pub fn protect(pid: Pid) -> Result<ProgramContextGuard> {
        let backup_regs = ptrace::getregs(pid)?;
        let backup_code = ptrace::read(pid, backup_regs.rip as *mut c_void)?;

        Ok(ProgramContextGuard {
            backup_regs,
            backup_code,
            pid,
        })
    }

    pub fn ip(&self) -> *mut c_void {
        self.backup_regs.rip as *mut c_void
    }

    pub fn regs(&self) -> user_regs_struct {
        self.backup_regs.clone()
    }

    pub fn set_regs(&self, regs: user_regs_struct) -> Result<()> {
        ptrace::setregs(self.pid, regs)?;

        Ok(())
    }

    fn write(&self, ptr: *mut c_void, data: *mut c_void) -> Result<()> {
        ptrace::write(self.pid, ptr, data)?;

        Ok(())
    }

    pub fn syscall(&self) -> Result<*mut c_void> {
        self.write(self.ip(), 0x050f as *mut c_void)?;
        self.step()?;

        let regs = ptrace::getregs(self.pid).unwrap();
        let ret = regs.rax as *mut c_void;

        Ok(ret)
    }

    pub fn call_and_int(&self) -> Result<u64> {
        self.write(self.ip(), 0xccd0ff as *mut c_void)?;
        self.cont()?;

        let regs = ptrace::getregs(self.pid).unwrap();
        let ret = regs.rax;

        Ok(ret)
    }

    fn cont(&self) -> Result<()> {
        ptrace::cont(self.pid, None)?;
        waitpid(self.pid, None)?;

        Ok(())
    }

    fn step(&self) -> Result<()> {
        ptrace::step(self.pid, None)?;
        waitpid(self.pid, None)?;

        Ok(())
    }
}

impl Drop for ProgramContextGuard {
    fn drop(&mut self) {
        ptrace::write(self.pid, self.ip(), self.backup_code as *mut c_void).unwrap();
        ptrace::setregs(self.pid, self.backup_regs).unwrap();
    }
}
