use backtrace::Backtrace;
use quick_error::quick_error;

use crate::maps::MapError;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Nix(err: nix::Error, backtrace: Backtrace) {
            from(err: nix::Error) -> (err, Backtrace::new())
        }
        Map(err: MapError, backtrace: Backtrace) {
            from(err: MapError) -> (err, Backtrace::new())
        }
        Io(err: std::io::Error, backtrace: Backtrace) {
            from(err: std::io::Error) -> (err, Backtrace::new())
        }
        Other(err: &'static str, backtrace: Backtrace) {
            from(err: &'static str) -> (err, Backtrace::new())
            from(err: std::option::NoneError) -> ("None Error", Backtrace::new())
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
