use regex::Regex;
use walkdir::DirEntry;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

/// to define whether a file is a valid rust source file
pub fn is_rs(entry: &DirEntry, re: &Regex) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| {
            if re.is_match(s) {
                return false;
            }
            s.ends_with(".rs")
        })
        .unwrap_or(false)
}

pub fn count_lines(entry: &DirEntry) -> i32 {
    let mut lines = 0;
    let path = entry.path().to_str().unwrap();
    let f = File::open(path).unwrap();
    let reader = BufReader::new(f);
    for _line in reader.lines() {
        lines += 1;
    }
    lines
}

