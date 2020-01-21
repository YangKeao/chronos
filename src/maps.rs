use std::fs::File;
use std::io::{Read, BufReader, BufRead};
use nix::unistd::Pid;
use quick_error::quick_error;

use itertools::Itertools;

quick_error! {
    #[derive(Debug)]
    pub enum MapError {
        Io(err: std::io::Error) {
            from()
        }
    }
}
pub type MapResult<T> = std::result::Result<T, MapError>;

pub struct Entry {
    pub start_addr: u64,
    pub end_addr: u64,
    pub privilege: String,
    pub padding_size: u64,
    pub path: String,
}

pub struct MapReader {
    file: BufReader<File>
}

impl MapReader {
    pub fn from_pid(pid: Pid) -> MapResult<MapReader> {
        Ok(MapReader {
            file: BufReader::new(File::open(format!("/proc/{}/maps", pid.as_raw()))?)
        })
    }
}

impl Iterator for MapReader {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: handle error here

        let mut line = String::new();
        self.file.read_line(&mut line);

        let mut section = line.split(" ");
        let addresses: &str = section.next()?;

        let (start_addr, end_addr): (&str, &str) = addresses.split("-").next_tuple()?;
        let (start_addr, end_addr): (u64, u64) = (
            u64::from_str_radix(start_addr, 16).ok()?,
            u64::from_str_radix(end_addr, 16).ok()?,
            );

        let privilege = section.next()?.to_owned();

        let padding_size: &str = section.next()?;
        let padding_size =  u64::from_str_radix(padding_size, 16).ok()?;

        let path: String = section.last()?.trim().to_owned();

        Some(Entry {
            start_addr,
            end_addr,
            privilege,
            padding_size,
            path,
        })
    }
}