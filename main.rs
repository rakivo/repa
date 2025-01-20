use std::env;
use std::fs::File;
use std::fmt::Display;
use std::process::ExitCode;
use std::io::{self, Write, BufWriter};

use memmap2::Mmap;
use rayon::prelude::*;

mod dir_rec;
use dir_rec::DirRec;

type Lps = Vec::<usize>;

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
    fn new(file_path: &String, row: usize, col: usize) -> Self {
        Self(format!("{file_path}:{row}:{col}:\n"))
    }

    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

fn construct_lps(pat: &str) -> Lps {
    let m = pat.len();
    let pat = pat.as_bytes();

    let mut n = 0;
    let mut i = 1;
    let mut lps = vec![0; m];
    while i < m {
        if pat[i] == pat[n] {
            n += 1;
            lps[i] = n;
            i += 1;
        } else if n != 0 {
            n = lps[n - 1];
        } else {
            lps[i] = 0;
            i += 1;
        }
    } lps
}

fn search(needle: &str, haystack: &[u8], lps: &Lps) -> Vec::<(usize, usize)> {
    let n = haystack.len();
    let m = needle.len();

    let needle = needle.as_bytes();

    let mut i = 0;
    let mut j = 0;
    let mut row = 1;
    let mut col = 1;
    let mut ret = Vec::new();
    while i < n {
        if haystack[i] == b'\n' {
            i += 1;
            col = 1;
            row += 1;
            continue
        }

        if haystack[i] == needle[j] {
            i += 1;
            j += 1;
            col += 1;
            if j == m {
                ret.push((row, col - m));
                j = lps[j - 1]
            }
        } else if j != 0 {
            j = lps[j - 1]
        } else {
            i += 1;
            col += 1
        }
    } ret
}

fn main() -> ExitCode {
    let args = env::args().collect::<Vec::<_>>();
    if args.len() < 3 {
        eprintln!("usage: {program} <pattern> <directory to search in>", program = args[0]);
        return ExitCode::FAILURE
    }

    // construct the Longest Prefix Suffix for the `KMP` algorithm
    let ref pat = args[1];
    let lps = construct_lps(pat);

    let ref dir_path = args[2];
    let dir = DirRec::new(dir_path);

    let results = dir.into_iter()
        .par_bridge()
        .filter(|e| e.as_path().is_file())
        .filter_map(|e| {
            let file = File::open(&e).unwrap();
            let mmap = unsafe { Mmap::map(&file).ok()? };
            Some((e, mmap))
        }).flat_map(|(e, mmap)| {
            let haystack = &mmap[..];
            let matches = search(pat, haystack, &lps);
            let path = e.as_path().to_string_lossy().to_string();
            matches.into_iter().map(move |(row, col)| {
                Loc::new(&path, row, col)
            }).par_bridge()
        }).collect::<Vec::<_>>();

    let mut stdout = BufWriter::new(io::stdout());
    results.iter().for_each(|loc| {
        _ = stdout.write_all(loc.as_bytes());
    });

    ExitCode::SUCCESS
}
