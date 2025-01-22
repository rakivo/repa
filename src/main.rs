use std::env;
use std::fs::File;
use std::ops::Not;
use std::path::Path;
use std::fmt::Display;
use std::process::ExitCode;
use std::os::unix::ffi::OsStrExt;

use memmap2::Mmap;
use dir_rec::DirRec;
use flager::{new_flag, Flag, Parser as FlagParser};
use hyperscan::{prelude::*, CompileFlags as HsFlag};

mod exts;
use exts::*;

const READ_BINARY: Flag::<bool> = new_flag!("-b", "--read-binary", false);
const CASE_SENSITIVE: Flag::<bool> = new_flag!("-c", "--case-sensitive", false);

#[repr(transparent)]
struct Loc(String);

impl Display for Loc {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter::<'_>) -> std::fmt::Result {
        write!(f, "{loc}", loc = self.0)
    }
}

impl Loc {
    #[inline(always)]
    fn new(file_path: &Path, row: usize, col: usize) -> Self {
        let file_path = file_path.display();
        Self(format!("{file_path}:{row}:{col}:"))
    }

    // O(n)
    #[inline]
    fn precompute(haystack: &[u8]) -> Vec::<usize> {
        let mut line_starts = vec![0];
        line_starts.extend(haystack.iter().enumerate().filter(|(.., c)| **c == b'\n').map(|(i, ..)| i + 1));
        line_starts
    }

    // O(log lines_count)
    #[inline]
    fn from_precomputed(line_starts: &[usize], index: usize, file_path: &Path) -> Self {
        let (row, col) = if let Some(line_number) = line_starts.binary_search_by(|&start| start.cmp(&index)).err() {
            let line_start = line_starts[line_number - 1];
            (line_number, index - line_start + 1)
        } else {
            (1, index + 1)
        };
        Self::new(file_path, row, col)
    }
}

#[inline]
fn search(pattern: &BlockDatabase, scratch: &mut Scratch, haystack: &[u8], path: &Path) {
    let line_starts = Loc::precompute(haystack);
    pattern.scan(haystack, scratch, |_, from, _, _| {
        println!{
            "{loc}",
            loc = Loc::from_precomputed(&line_starts, from as _, path)
        };
        Matching::Continue
    }).unwrap();
}

#[inline]
fn search_binary(pattern: &BlockDatabase, scratch: &mut Scratch, haystack: &[u8], path: &Path) {
    let file_path = path.display();
    pattern.scan(haystack, scratch, |_, _, _, _| {
        println!("binary file matched: {file_path}");
        Matching::Continue
    }).unwrap();
}

#[inline]
fn nth_not_starting_with_dash(n: usize, args: &Vec::<String>) -> Option::<&String> {
    args[1..].iter().filter(|s| s.starts_with('-').not()).nth(n)
}

fn main() -> ExitCode {
    let args = env::args().collect::<Vec::<_>>();
    if args.len() < 3 {
        eprintln!{
            "usage: {program} <pattern> <directory to search in> [...flags]",
            program = args[0]
        };
        return ExitCode::FAILURE
    }

    let flag_parser = FlagParser::new();
    let read_binary = flag_parser.parse_or_default(&READ_BINARY);
    let case_sensitive = flag_parser.parse_or_default(&CASE_SENSITIVE);

    let Some(pattern_str) = nth_not_starting_with_dash(0, &args) else {
        return ExitCode::FAILURE
    };
    let mut hsflags = HsFlag::SOM_LEFTMOST;
    if !case_sensitive {
        hsflags |= HsFlag::CASELESS
    }
    let pattern = pattern! {
        pattern_str;
        HsFlag::SOM_LEFTMOST
    };
    let pattern_db = pattern.build().unwrap();
    let mut scratch = pattern_db.alloc_scratch().unwrap();

    let Some(dir_path) = nth_not_starting_with_dash(1, &args) else {
        return ExitCode::FAILURE
    };
    let dir = DirRec::new(dir_path);

    dir.into_iter()
        .filter_map(|e| {
            let path = e.as_path();
            let is_binary = path.extension()
                .map(|ext| BINARY_EXTENSIONS.contains(ext.as_bytes()))
                .unwrap_or(true)
                .not();
            if is_binary && !read_binary {
                None
            } else {
                Some((e, is_binary))
            }
        }).filter_map(|(e, is_binary)| {
            let file = File::open(&e).unwrap();
            let mmap = unsafe { Mmap::map(&file) }.ok()?;
            Some((e, mmap, is_binary))
        }).for_each(|(e, mmap, is_binary)| {
            if is_binary {
                search_binary(&pattern_db, &mut scratch, &mmap[..], e.as_path())
            } else {
                search(&pattern_db, &mut scratch, &mmap[..], e.as_path())
            }
        });

    ExitCode::SUCCESS
}
