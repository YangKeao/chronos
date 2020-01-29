use libc::{clockid_t, dlerror, dlopen, dlsym, syscall, timespec};
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::ptr::null;

#[no_mangle]
pub static mut TV_SEC_DELTA: c_long = 0;

#[no_mangle]
pub static mut TV_NSEC_DELTA: c_long = 0;

#[no_mangle]
pub unsafe extern "C" fn fake_clock_gettime(clk_id: clockid_t, res: *mut timespec) -> c_int {
    let ret = syscall(228, clk_id, res);
    (*res).tv_sec += TV_SEC_DELTA;
    (*res).tv_nsec += TV_NSEC_DELTA;

    ret as c_int
}
