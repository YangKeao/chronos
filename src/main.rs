#![feature(try_trait)]

use clap::{value_t, App, Arg};
use nix::unistd::Pid;

use crate::error::Result;
use crate::program::Program;
use std::os::raw::c_long;

use log::*;

mod error;
mod maps;
mod program;

fn inject(pid: Pid, fake_image: String, tv_sec_delta: c_long, tv_nsec_delta: c_long) -> Result<()> {
    info!("tracing program {}", pid);
    let mut program = program::Program::ptrace(pid)?;

    info!("parsing vdso");
    let vdso_entry = program.select_lib(Program::generate_name_lib_selector("[vdso]"))?;
    let real_addr = program.get_func_in_lib("clock_gettime", vdso_entry)?;
    info!("get clock_gettime address at {:?}", real_addr);

    info!("dlopening fake_image at {}", &fake_image);
    let handle = program.dlopen(fake_image)?;
    let fake_addr = program.dlsym(handle, "fake_clock_gettime")?;
    info!("get fake_clock_gettime addr at {:?}", fake_addr);

    info!("replacing function");
    program.hard_replace_fun(real_addr, fake_addr)?;

    info!("setting delta time for fake_image");
    let tv_sec_delta =
        unsafe { std::mem::transmute::<c_long, [u8; std::mem::size_of::<c_long>()]>(tv_sec_delta) };
    let tv_sec_delta_ptr = program.dlsym(handle, "TV_SEC_DELTA")?;
    program.write_slice(&tv_sec_delta, tv_sec_delta_ptr)?;

    let tv_nsec_delta = unsafe {
        std::mem::transmute::<c_long, [u8; std::mem::size_of::<c_long>()]>(tv_nsec_delta)
    };
    let tv_nsec_delta_ptr = program.dlsym(handle, "TV_NSEC_DELTA")?;
    program.write_slice(&tv_nsec_delta, tv_nsec_delta_ptr)?;

    info!("continue");
    program.cont()?;

    Ok(())
}

fn main() {
    env_logger::init();

    let matches = App::new("Chronos")
        .version("0.1.0")
        .author("Yang Keao <keao.yang@yahoo.com>")
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("pid")
                .takes_value(true)
                .help("the pid of process to inject")
                .required(true),
        )
        .arg(
            Arg::with_name("fake")
                .short("f")
                .long("fake")
                .takes_value(true)
                .help("the absolute path of fake image of clock_gettime")
                .required(true),
        )
        .arg(
            Arg::with_name("tv_sec_delta")
                .short("s")
                .long("tv_sec_delta")
                .takes_value(true)
                .help("delta of tv_sec_delta field")
                .required(true),
        )
        .arg(
            Arg::with_name("tv_nsec_delta")
                .short("n")
                .long("tv_nsec_delta")
                .takes_value(true)
                .help("delta of tv_nsec_delta field")
                .required(true),
        )
        .get_matches();

    let pid: i32 = match value_t!(matches, "pid", i32) {
        Ok(pid) => pid,
        Err(e) => {
            error!("cannot get pid argument: {}", e);
            return;
        }
    };
    let pid: Pid = Pid::from_raw(pid);

    let fake_image: String = match value_t!(matches, "fake", String) {
        Ok(fake) => fake,
        Err(e) => {
            error!("cannot get fake argument: {}", e);
            return;
        }
    };

    let tv_sec_delta: c_long = match value_t!(matches, "tv_sec_delta", c_long) {
        Ok(s) => s,
        Err(e) => {
            error!("cannot get tv_sec_delta argument: {}", e);
            return;
        }
    };

    let tv_nsec_delta: c_long = match value_t!(matches, "tv_nsec_delta", c_long) {
        Ok(n) => n,
        Err(e) => {
            error!("cannot get tv_nsec_delta argument: {}", e);
            return;
        }
    };

    if let Err(e) = inject(pid, fake_image, tv_sec_delta, tv_nsec_delta) {
        error!("inject error {}", e);
    }
}
