use std::env;
use std::fs::File;
use std::path::Path;
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
    const AVG_LINE_SIZE: usize = 32;

    #[inline(always)]
    fn new(file_path: &Path, row: usize, col: usize) -> Self {
        let file_path = file_path.display();
        Self(format!("{file_path}:{row}:{col}:\n"))
    }

    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    // O(index)
    #[inline]
    fn from_bytes(bytes: &[u8], index: usize, file_path: &Path) -> Self {
        let mut row = 1;
        let mut last_newline = 0;
        bytes.iter().enumerate().take(index + 1).filter(|(.., c)| **c == b'\n').for_each(|(i, ..)| {
            row += 1;
            last_newline = i + 1
        });
        Self::new(file_path, row, index - last_newline + 1)
    }

    #[inline(always)]
    fn is_precomputation_needed(file_size: usize, matches_len: usize) -> bool {
        file_size / (Self::AVG_LINE_SIZE * (file_size as f64).log2() as usize) >= matches_len
    }

    // O(n)
    fn precompute(haystack: &[u8]) -> Vec::<usize> {
        let mut line_starts = vec![0];
        line_starts.extend(haystack.iter().enumerate().filter(|(.., c)| **c == b'\n').map(|(i, ..)| {
            i + 1
        })); line_starts
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

fn search(needle: &str, haystack: &[u8], lps: &Lps) -> Vec::<usize> {
    let n = haystack.len();
    let m = needle.len();

    let needle = needle.as_bytes();

    let mut i = 0;
    let mut j = 0;
    let mut ret = Vec::new();
    while i < n {
        if haystack[i] == needle[j] {
            i += 1;
            j += 1;
            if j == m {
                ret.push(i - j);
                j = lps[j - 1]
            }
        } else if j != 0 {
            j = lps[j - 1]
        } else {
            i += 1
        }
    } ret
}

fn main() -> ExitCode {
    let args = env::args().collect::<Vec::<_>>();
    if args.len() < 3 {
        eprintln!("usage: {program} <needletern> <directory to search in>", program = args[0]);
        return ExitCode::FAILURE
    }

    let ref dir_path = args[1];
    let dir = DirRec::new(dir_path);

    // construct the Longest Prefix Suffix for the `KMP` algorithm
    let ref pat = args[2];
    let lps = construct_lps(pat);

    let results = dir.into_iter()
        .par_bridge()
        .filter(|e| e.as_path().is_file())
        .filter_map(|e| {
            let file = File::open(&e).unwrap();
            let mmap = unsafe { Mmap::map(&file).ok()? };
            Some((e, mmap))
        }).fold(|| Vec::new(), |mut locs, (e, haystack)| {
            let path = e.as_path();
            let haystack = &haystack[..];
            let matches = search(pat, haystack, &lps);
            if Loc::is_precomputation_needed(haystack.len(), matches.len()) {
                locs.extend(matches.into_iter().map(|index| {
                    Loc::from_bytes(haystack, index, path)
                }))
            } else {
                let ls = Loc::precompute(haystack);
                locs.extend(matches.into_iter().map(|index| {
                    Loc::from_precomputed(&ls, index, path)
                }))
            } locs
        }).reduce(Vec::new, |_, locs| locs);

    let mut stdout = BufWriter::new(io::stdout());
    results.iter().for_each(|loc| {
        _ = stdout.write_all(loc.as_bytes());
    });

    ExitCode::SUCCESS
}
