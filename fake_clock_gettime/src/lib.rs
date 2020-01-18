use libc::{clock_gettime, clockid_t, timespec};
use std::os::raw::{c_long, c_int};

#[no_mangle]
pub static TV_SEC_DELTA: c_long = 0;

#[no_mangle]
pub static TV_NSEC_DELTA: c_long = 0;

#[no_mangle]
pub extern "C" fn fake_clock_gettime(clk_id: clockid_t , res: *mut timespec) -> c_int {
    println!("injected clock_gettime!");

    let ret = unsafe {clock_gettime(clk_id, res)};

    unsafe {
        (*res).tv_sec += TV_SEC_DELTA;
        (*res).tv_nsec += TV_NSEC_DELTA;
    }

    ret
}