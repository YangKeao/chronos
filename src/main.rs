#![feature(try_trait)]

use clap::{App, Arg, value_t};
use nix::unistd::Pid;

use std::os::unix::io::AsRawFd;
use std::os::raw::{c_long, c_void};
use crate::program::Program;

mod program;
mod error;
mod maps;

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

    let mut fake_image: String = value_t!(matches, "fake", String).unwrap();

    let mut program = program::Program::ptrace(pid).unwrap();

    let vdso_entry = program.select_lib(Program::generate_name_lib_selector("[vdso]")).unwrap();
    let real_addr = program.get_func_in_lib("clock_gettime", vdso_entry).unwrap();
    let handle = program.dlopen(fake_image.clone()).unwrap();
    let fake_addr = program.dlsym(handle, "fake_clock_gettime").unwrap();

    program.hard_replace_fun(real_addr, fake_addr);

    let tv_sec_delta = unsafe{std::mem::transmute::<c_long, [u8; std::mem::size_of::<c_long>()]>(24833183051058)};
    let tv_sec_delta_ptr = program.dlsym(handle, "TV_SEC_DELTA").unwrap();
    program.write_slice(&tv_sec_delta, tv_sec_delta_ptr).unwrap();

    let tv_nsec_delta = unsafe{std::mem::transmute::<c_long, [u8; std::mem::size_of::<c_long>()]>(24833183051058)};
    let tv_nsec_delta_ptr = program.dlsym(handle, "TV_NSEC_DELTA").unwrap();
    program.write_slice(&tv_nsec_delta, tv_nsec_delta_ptr).unwrap();

    program.cont();
}
