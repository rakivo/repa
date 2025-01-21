use std::env;
use std::fs::File;
use std::fmt::Display;
use std::ops::Not;
use std::path::Path;
use std::os::unix::ffi::OsStrExt;
use std::process::ExitCode;

use memmap2::Mmap;
use dir_rec::DirRec;
use hyperscan::prelude::*;

mod exts;
use exts::*;

#[repr(transparent)]
struct Loc(String);

impl Display for Loc {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

fn main() -> ExitCode {
    let args = env::args().collect::<Vec::<_>>();
    if args.len() < 3 {
        eprintln!{
            "usage: {program} <pattern> <directory to search in>",
            program = args[0]
        };
        return ExitCode::FAILURE
    }

    let ref pattern_str = args[1];
    let pattern = pattern! {
        pattern_str;
        hyperscan::CompileFlags::SOM_LEFTMOST
    };
    let pattern_db = pattern.build().unwrap();
    let mut scratch = pattern_db.alloc_scratch().unwrap();

    let ref dir_path = args[2];
    let dir = DirRec::new(dir_path);

    dir.into_iter()
        .filter(|e| {
            let path = e.as_path();
            if !path.is_file() { return false }
            path.extension()
                .map(|ext| BINARY_EXTENSIONS.contains(ext.as_bytes()))
                .unwrap_or(true)
                .not()
        }).filter_map(|e| {
            let file = File::open(&e).unwrap();
            let mmap = unsafe { Mmap::map(&file) }.ok()?;
            Some((e, mmap))
        }).for_each(|(e, mmap)| {
            search(&pattern_db, &mut scratch, &mmap[..], e.as_path());
        });

    ExitCode::SUCCESS
}
