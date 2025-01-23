use std::env;
use std::fs::File;
use std::ops::Not;
use std::fmt::Display;
use std::process::ExitCode;
use std::path::{Path, PathBuf};
use std::os::unix::ffi::OsStrExt;

use memmap2::Mmap;
use dir_rec::DirRec;
use flager::{new_flag, Flag, Parser as FlagParser};

#[cfg(feature = "regex")]
use regex_automata::{
    Input,
    nfa::thompson,
    util::syntax::Config,
    dfa::{dense, Automaton}
};
#[cfg(feature = "hyperscan")]
use hyperscan::{
    prelude::*,
    CompileFlags as HsFlag
};

mod exts;
use exts::*;

const HELP: Flag = new_flag!("-h", "--help").help("print this text and exit");
const READ_BINARY: Flag::<bool> = new_flag!("-b", "--read-binary", false).help("do not read binary files");
const CASE_SENSITIVE: Flag::<bool> = new_flag!("-c", "--case-sensitive", false).help("do case sensitive search");

macro_rules! printdoc {
    (usage $program: expr) => {
        println!("usage: {} <pattern> <directory to search in> [...flags]", $program)
    };
    (example $program: expr) => {
        println!("example: {} linear docs.gl", $program)
    };
}

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

#[cfg(feature = "regex")]
struct SearchCtx {
    dfa: dense::DFA::<Vec::<u32>>,
    read_binary: bool
}

#[cfg(feature = "hyperscan")]
struct SearchCtx {
    scratch: Scratch,
    pattern_db: BlockDatabase,
    read_binary: bool
}

impl SearchCtx {
    #[inline]
    fn new(pattern_str: &str, read_binary: bool, case_sensitive: bool) -> Self {
        #[cfg(feature = "hyperscan")] {
            let mut hsflags = HsFlag::SOM_LEFTMOST;
            if !case_sensitive {
                hsflags |= HsFlag::CASELESS
            }
            let pattern = pattern! {
                pattern_str;
                HsFlag::SOM_LEFTMOST
            };
            let pattern_db = pattern.build().unwrap();
            let scratch = pattern_db.alloc_scratch().unwrap();
            SearchCtx { scratch, pattern_db, read_binary }
        }

        #[cfg(feature = "regex")] {
            let cfg = Config::new().case_insensitive(case_sensitive);
            let dfa = dense::Builder::new()
                .syntax(cfg)
                .thompson(thompson::Config::new().reverse(true))
                .build(pattern_str)
                .unwrap();
            SearchCtx { dfa, read_binary }
        }
    }

    #[inline]
    fn filter(&self, e: PathBuf) -> Option::<(PathBuf, bool)> {
        let path = e.as_path();
        let is_binary = path.extension()
            .map(|ext| BINARY_EXTENSIONS.contains(ext.as_bytes()))
            .unwrap_or(true);
        if is_binary && !self.read_binary {
            None
        } else {
            Some((e, is_binary))
        }
    }

    #[inline]
    fn search(&self, haystack: &[u8], path: &Path, is_binary: bool) {
        #[inline(always)]
        fn print_loc(line_starts: &[usize], index: usize, file_path: &Path, is_binary: bool) {
            println!{
                "{loc}{isbin}",
                loc = Loc::from_precomputed(&line_starts, index, file_path),
                isbin = if is_binary { "[binary]" } else { "" },
            };
        }

        let line_starts = Loc::precompute(haystack);

        #[cfg(feature = "hyperscan")] {
            self.pattern_db.scan(haystack, &self.scratch, |_, from, _, _| {
                print_loc(&line_starts, from as _, path, is_binary);
                Matching::Continue
            }).unwrap();
        }

        #[cfg(feature = "regex")] {
            let mut input = Input::new(haystack);
            loop {
                let Ok(result) = self.dfa.try_search_rev(&input) else {
                    continue
                };
                match result {
                    None => break,
                    Some(hm) => {
                        print_loc(&line_starts, hm.offset(), path, is_binary);
                        if hm.offset() == 0 || input.end() == 0 {
                            break
                        } else if hm.offset() < input.end() {
                            input.set_end(hm.offset());
                        } else {
                            input.set_end(input.end() - 1);
                        }
                    }
                }
            }
        }
    }
}

#[inline]
fn nth_not_starting_with_dash(n: usize, args: &Vec::<String>) -> Option::<&String> {
    args[1..].iter().filter(|s| s.starts_with('-').not()).nth(n)
}

fn main() -> ExitCode {
    let args = env::args().collect::<Vec::<_>>();
    let ref program = args[0];
    let flag_parser = FlagParser::new();
    if flag_parser.passed(&HELP) {
        printdoc!(usage program);
        printdoc!(example program);
        println!("flags:");
        println!("  {READ_BINARY}");
        println!("  {CASE_SENSITIVE}");
        return ExitCode::SUCCESS
    }

    if args.len() < 3 {
        printdoc!(usage program);
        printdoc!(example program);
        return ExitCode::FAILURE
    }

    let read_binary = flag_parser.passed(&READ_BINARY);
    let case_sensitive = flag_parser.passed(&CASE_SENSITIVE);

    let Some(pattern_str) = nth_not_starting_with_dash(0, &args) else {
        return ExitCode::FAILURE
    };
    let search_ctx = SearchCtx::new(pattern_str, read_binary, case_sensitive);

    let Some(dir_path) = nth_not_starting_with_dash(1, &args) else {
        return ExitCode::FAILURE
    };
    let dir = DirRec::new(dir_path);

    dir.into_iter()
        .filter_map(|e| search_ctx.filter(e))
        .filter_map(|(e, is_binary)| {
            let file = File::open(&e).unwrap();
            let mmap = unsafe { Mmap::map(&file) }.ok()?;
            Some((e, mmap, is_binary))
        }).for_each(|(e, mmap, is_binary)| {
            search_ctx.search(&mmap[..], e.as_path(), is_binary)
        });

    ExitCode::SUCCESS
}
