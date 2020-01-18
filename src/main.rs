use clap::{App, Arg, value_t};
use nix::sys::ptrace;
use nix::unistd::Pid;
use nix::sys::wait::waitpid;
use std::ffi::{c_void, CStr};
use std::io::Read;
use goblin::Object;
use std::os::raw::c_int;

fn replace_func(pid: Pid, func_name: &[u8], new_func_addr: *mut c_void) {
    let mut running_program = std::fs::File::open(format!("/proc/{}/exe", pid)).unwrap();
    let real_path = std::fs::read_link(format!("/proc/{}/exe", pid)).unwrap();

    let mut running_program_buffer = Vec::new();
    running_program.read_to_end(&mut running_program_buffer).unwrap();

    let mut func_plt_addr = 0;
    match Object::parse(&running_program_buffer).unwrap() {
        Object::Elf(elf) => {
            for (index, reloc) in elf.pltrelocs.iter().enumerate() {
                let symbol = elf.dynsyms.get(reloc.r_sym).unwrap();
                let name = elf.dynstrtab.get(symbol.st_name).unwrap();

                match name {
                    Ok(name) => {
                        if name.as_bytes() == func_name {
                            println!("{} is at index: {} in .plt", name, index + 1);

                            let mut plt_entry_size = 0;
                            let mut plt_addr = 0;

                            for header in elf.section_headers.iter() {
                                let header_name = elf.shdr_strtab.get(header.sh_name).unwrap();
                                match header_name {
                                    Ok(".plt") => {
                                        plt_entry_size = header.sh_entsize;
                                        plt_addr = header.sh_addr;

                                        println!(".plt section found at {} with entry size {}", plt_addr, plt_entry_size);
                                    }
                                    _ => {}
                                }
                            }

                            let plt_func_offset = ((index + 1) as u64) * plt_entry_size + plt_addr;
                            let mut maps = std::fs::File::open(format!("/proc/{}/maps", pid)).unwrap();
                            let mut maps_content = String::new();

                            maps.read_to_string(&mut maps_content);
                            let self_real_line = maps_content.lines().filter(|line| {
                                line.contains(real_path.to_str().unwrap())
                            }).next().unwrap();

                            let self_global_offset: String = self_real_line.split(" ").nth(2).unwrap().to_owned();
                            let self_global_offset = u64::from_str_radix(&self_global_offset, 16).unwrap() as usize;

                            let base_addr: String = self_real_line.split("-").next().unwrap().to_owned();
                            let base_addr = u64::from_str_radix(&base_addr, 16).unwrap() as *mut c_void;

                            let func_plt_ptr = unsafe {base_addr.add(plt_func_offset as usize).sub(self_global_offset)};
                            println!("{}@plt is at {:?}", std::str::from_utf8(func_name).unwrap(), func_plt_ptr);

                            func_plt_addr = func_plt_ptr as u64;
                        }
                    }
                    _ => {

                    }
                }
            }
        },
        _ => {
            unreachable!();
        }
    }

    let mut instructions: Vec<u8> = vec![0;16];
    instructions[0] = 0x48;
    instructions[1] = 0xb8;
    unsafe {
        *(&mut instructions[2] as *mut u8 as *mut u64) = new_func_addr as u64;
    }
    instructions[10] = 0xff;
    instructions[11] = 0xe0;

    let first_part = unsafe {
        *(&instructions[0] as *const u8 as *const u64)
    };
    let second_part = unsafe {
        *(&instructions[8] as *const u8 as *const u64)
    };
    ptrace::write(pid, func_plt_addr as *mut c_void, first_part as *mut c_void);
    ptrace::write(pid, (func_plt_addr + 8) as *mut c_void, second_part as *mut c_void);
}

fn map_func_address(pid: Pid, filename: &[u8], func_name: &[u8]) -> *mut c_void {
    let mut maps = std::fs::File::open(format!("/proc/{}/maps", pid)).unwrap();
    let mut maps_content = String::new();

    maps.read_to_string(&mut maps_content);
    let libcs: Vec<&str> = maps_content.lines().filter(|line| {
        line.contains("/libc-") && line.contains("r-xp")
    }).collect();

    let libc_line = libcs[0].to_owned();

    let libc_global_offset: String = libc_line.split(" ").nth(2).unwrap().to_owned();
    let libc_global_offset = u64::from_str_radix(&libc_global_offset, 16).unwrap() as usize;

    let base_addr: String = libc_line.split("-").next().unwrap().to_owned();
    let base_addr = u64::from_str_radix(&base_addr, 16).unwrap() as *mut c_void;
    println!("get libc base_addr: {:?}", base_addr);

    let libc_file_path: String = libc_line.split(" ").last().unwrap().to_owned();
    let mut libc_file = std::fs::File::open(libc_file_path).unwrap();
    let mut libc_buffer = Vec::new();
    libc_file.read_to_end(&mut libc_buffer).unwrap();

    let mut dlopen_offset: usize = 0;
    let mut dlsym_offset: usize = 0;

    match Object::parse(&libc_buffer).unwrap() {
        Object::Elf(elf) => {
            for dynsym in elf.dynsyms.iter() {
                let name = elf.dynstrtab.get(dynsym.st_name).unwrap();
                match name {
                    Ok("__libc_dlopen_mode") => {
                        dlopen_offset = dynsym.st_value as usize;
                        println!("get dlopen offset {}", dlopen_offset);
                    }
                    Ok("__libc_dlsym") => {
                        dlsym_offset = dynsym.st_value as usize;
                        println!("get dlsym offset {}", dlsym_offset);
                    }
                    _ => {}
                }
            }
        },
        _ => {
            unreachable!();
        }
    }

    let dlopen_addr = unsafe {base_addr.add(dlopen_offset).sub(libc_global_offset) };
    println!("get dlopen addr {:?}", dlopen_addr);
    let dlsym_addr = unsafe {base_addr.add(dlsym_offset).sub(libc_global_offset)};
    println!("get dlsym addr {:?}", dlsym_addr);

    let handle = {
        let backup_regs = ptrace::getregs(pid).unwrap();
        let ip = backup_regs.rip as *mut c_void;
        let backup_code = ptrace::read(pid, ip).unwrap();

        let mut regs = backup_regs.clone();
        regs.rax = dlopen_addr as u64;        // dlopen
        regs.rdi = alloc_string(pid, filename) as u64;        // filename
        regs.rsi = 1;   // RTLD_LAZY

        ptrace::setregs(pid, regs).unwrap();
        ptrace::write(pid, ip, 0xccd0ff as *mut c_void); // call
        ptrace::cont(pid, None);

        waitpid(pid, None).unwrap();
        let regs = ptrace::getregs(pid).unwrap();
        let handle = regs.rax as *mut c_void;
        ptrace::write(pid, ip, backup_code as *mut c_void).unwrap();
        ptrace::setregs(pid, backup_regs).unwrap();

        let backup_regs = ptrace::getregs(pid).unwrap();
        let ip = backup_regs.rip as *mut c_void;
        let backup_code = ptrace::read(pid, ip).unwrap();

        println!("fake image handle is at {:?}", handle);
        handle
    };

    let func_addr = {
        let backup_regs = ptrace::getregs(pid).unwrap();
        let ip = backup_regs.rip as *mut c_void;
        let backup_code = ptrace::read(pid, ip).unwrap();

        let mut regs = backup_regs.clone();
        regs.rax = dlsym_addr as u64;         // dlsym
        regs.rdi = handle as u64;        // handle
        regs.rsi = alloc_string(pid, func_name) as u64;   // symbol

        ptrace::setregs(pid, regs).unwrap();
        ptrace::write(pid, ip, 0xccd0ff as *mut c_void); // call
        ptrace::cont(pid, None);

        waitpid(pid, None).unwrap();
        let regs = ptrace::getregs(pid).unwrap();
        let addr = regs.rax as *mut c_void;
        ptrace::write(pid, ip, backup_code as *mut c_void).unwrap();
        ptrace::setregs(pid, backup_regs).unwrap();

        let backup_regs = ptrace::getregs(pid).unwrap();
        let ip = backup_regs.rip as *mut c_void;
        let backup_code = ptrace::read(pid, ip).unwrap();

        addr
    };

    println!("{} is at {:?}", std::str::from_utf8(func_name).unwrap(), func_addr);

    func_addr
}

fn alloc_string(pid: Pid, s: &[u8]) -> *mut c_void {
    let addr = mmap_in_another_process(pid, s.len(), 0);
    poke_bytes_into_addr(pid, s, addr);

    addr
}

fn poke_bytes_into_addr(pid: Pid, bytes: &[u8], addr: *mut c_void) {
    for (index, byte) in bytes.iter().enumerate() {
        ptrace::write(pid, unsafe {addr.add(index)}, *byte as *mut c_void).unwrap(); // TODO: use process_vm_writev to accelerate it
    }

    ptrace::write(pid, unsafe {addr.add(bytes.len())}, 0 as *mut c_void).unwrap();
}

fn mmap_in_another_process(pid: Pid, length: usize, fd: u64) -> *mut c_void {
    let backup_regs = ptrace::getregs(pid).unwrap();
    let ip = backup_regs.rip as *mut c_void;

    let backup_code = ptrace::read(pid, ip).unwrap();

    let mut regs = backup_regs.clone();
    regs.rax = 9;        // mmap
    regs.rdi = 0;        // addr
    regs.rsi = length as u64;   // length
    regs.rdx = 7;        // prot
    regs.r10 = 0x22;     // flags
    regs.r8 = fd;         // fd
    regs.r9 = 0;         // offset

    ptrace::setregs(pid, regs).unwrap();
    ptrace::write(pid, ip, 0x050f as *mut c_void); // syscall

    ptrace::step(pid, None);

    waitpid(pid, None).unwrap();
    let regs = ptrace::getregs(pid).unwrap();
    let ret = regs.rax as *mut c_void;
    println!("allocate page at {:?}", ret);

    ptrace::write(pid, ip, backup_code as *mut c_void).unwrap();
    ptrace::setregs(pid, backup_regs).unwrap();

    ret
}

fn main() {
    let matches = App::new("Chronos")
        .version("0.1.0")
        .author("Yang Keao <keao.yang@yahoo.com>")
        .arg(Arg::with_name("pid")
            .short("p")
            .long("pid")
            .takes_value(true)
            .help("the pid of process to inject")
            .required(true))
        .arg(Arg::with_name("fake")
            .short("f")
            .long("fake")
            .takes_value(true)
            .help("the absolute path of fake image of clock_gettime")
            .required(true))
        .get_matches();

    let pid: i32 = value_t!(matches, "pid", i32).unwrap();
    let pid: Pid = Pid::from_raw(pid);

    println!("injecting pid {}", pid);

    let mut fake_image: String = value_t!(matches, "fake", String).unwrap();

    ptrace::attach(pid).unwrap();
    waitpid(pid, None).unwrap();

    let addr = map_func_address(pid, fake_image.as_bytes(), b"fake_clock_gettime");
    replace_func(pid, b"clock_gettime", addr);

    ptrace::cont(pid, None).unwrap();
}
