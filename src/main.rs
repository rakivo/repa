use std::fs::File;
use std::ops::Not;
use std::{ptr, env};
use std::fmt::Display;
use std::io::{self, Read};
use std::process::ExitCode;
use std::path::{Path, PathBuf};

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
use hyperscan::prelude::*;

mod exts;
use exts::*;

const HELP: Flag = new_flag!("-h", "--help").help("print this text and exit");
const READ_BINARY: Flag = new_flag!("-b", "--read-binary").help("do not read binary files");
const ENABLE_UNICODE: Flag = new_flag!("-u", "--enable-unicode").help("enable unicode");
const CASE_SENSITIVE: Flag = new_flag!("-c", "--case-sensitive").help("do case sensitive search");
const MATCH_WHOLE_WORDS: Flag = new_flag!("-w", "--whole-words").help("match only whole words");

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
    fn new(file_path: Option::<&Path>, row: usize, col: usize) -> Self {
        if let Some(f) = file_path {
            let file_path = f.display();
            Self(format!("{file_path}:{row}:{col}:"))
        } else {
            Self(format!("?:{row}:{col}:"))
        }
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
    fn from_precomputed(line_starts: &[usize], index: usize, file_path: Option::<&Path>) -> (Self, usize) {
        let (row, col, line_number) = if let Some(line_number) = line_starts.binary_search_by(|&start| start.cmp(&index)).err() {
            let line_start = line_starts[line_number - 1];
            (line_number, index - line_start + 1, line_number)
        } else {
            (1, index + 1, 1)
        };
        (Self::new(file_path, row, col), line_number)
    }
}

#[cfg(feature = "regex")]
struct SearchCtx {
    dfa: dense::DFA::<Vec::<u32>>,
    read_binary: bool,
}

#[cfg(feature = "hyperscan")]
struct SearchCtx {
    scratch: Scratch,
    pattern_db: BlockDatabase,
    read_binary: bool,
}

impl SearchCtx {
    const MAXIMUM_PREVIEW_LEN: usize = 125;

    #[inline]
    fn new(flag_parser: &FlagParser, pattern_str: &str) -> Result::<Self, String> {
        let read_binary = flag_parser.passed(&READ_BINARY);
        let case_sensitive = flag_parser.passed(&CASE_SENSITIVE);
        let match_whole_words = flag_parser.passed(&MATCH_WHOLE_WORDS);

        #[cfg(feature = "hyperscan")] {
            let pattern = if match_whole_words {
                format!("(^|[^a-zA-Z0-9_]){pattern_str}([^a-zA-Z0-9_]|$)")
            } else {
                pattern_str.to_owned()
            };
            let pattern = if !case_sensitive {
                pattern!{pattern; SOM_LEFTMOST | CASELESS}
            } else {
                pattern!{pattern; SOM_LEFTMOST}
            };
            let pattern_db = pattern.build().map_err(|e| e.to_string())?;
            let scratch = pattern_db.alloc_scratch().unwrap();
            Ok(SearchCtx { scratch, pattern_db, read_binary })
        }

        #[cfg(feature = "regex")] {
            let pattern = if match_whole_words {
                format!("(?-u)\\b{pattern_str}\\b")
            } else {
                pattern_str.to_owned()
            };
            let cfg = Config::new().case_insensitive(case_sensitive);
            let dfa = dense::Builder::new()
                .syntax(cfg)
                .thompson(thompson::Config::new().reverse(true))
                .build(&pattern)
                .map_err(|e| e.to_string())?;
            Ok(SearchCtx { dfa, read_binary })
        }
    }

    #[inline]
    fn filter(&self, e: PathBuf) -> Option::<(PathBuf, bool)> {
        let path = e.as_path();
        let is_binary = path.extension()
            .map(|ext| BINARY_EXTENSIONS.contains(ext.as_encoded_bytes()))
            .unwrap_or(true);
        if is_binary && !self.read_binary {
            None
        } else {
            Some((e, is_binary))
        }
    }

    #[inline]
    fn search(&self, haystack: &[u8], path: Option::<&Path>) {
        #[inline(always)]
        fn print_match(line_starts: &[usize], index: usize, file_path: Option::<&Path>, haystack: &[u8]) {
            let (loc, line_number) = Loc::from_precomputed(&line_starts, index, file_path);

            let line_start = line_starts[line_number - 1];
            let line_end = if line_number < line_starts.len() {
                line_starts[line_number]
            } else {
                line_start + SearchCtx::MAXIMUM_PREVIEW_LEN.min(haystack.len())
            };

            let line_bytes = &haystack[line_start..line_end - 1];
            let preview = match std::str::from_utf8(line_bytes) {
                Ok(s) => {
                    let mut ch_count = 0;
                    let mut byte_count = 0;
                    for ch in s.chars() {
                        if ch_count >= SearchCtx::MAXIMUM_PREVIEW_LEN { break }
                        byte_count += ch.len_utf8();
                        ch_count += 1
                    }
                    &line_bytes[..byte_count]
                }
                Err(..) => b"<invalid UTF-8>"
            };

            let preview = unsafe { std::str::from_utf8_unchecked(preview) };
            println!("{loc}{preview}")
        }

        let line_starts = Loc::precompute(haystack);

        #[cfg(feature = "hyperscan")] {
            self.pattern_db.scan(haystack, &self.scratch, |_, from, _, _| {
                print_match(&line_starts, from as _, path, haystack);
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
                        print_match(&line_starts, hm.offset(), path, haystack);
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

#[cfg(unix)]
fn stdin_has_data() -> io::Result::<bool> {
    use std::mem;
    use libc::{select, timeval, FD_SET, FD_ZERO, FD_ISSET};

    unsafe {
        let mut fds = mem::zeroed();
        let mut timeout = timeval {
            tv_sec: 0,
            tv_usec: 0,
        };

        let stdin_fd = libc::STDIN_FILENO;

        FD_ZERO(&mut fds);
        FD_SET(stdin_fd, &mut fds);

        let ret = select(
            stdin_fd + 1,
            &mut fds,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut timeout
        );

        if ret == -1 {
            return Err(io::Error::last_os_error())
        }

        Ok(FD_ISSET(stdin_fd, &fds))
    }
}

#[cfg(windows)]
fn stdin_has_data() -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use winapi::um::namedpipeapi::PeekNamedPipe;
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;

    unsafe {
        let stdin_handle = io::stdin().as_raw_handle() as _;
        if stdin_handle == INVALID_HANDLE_VALUE as _ {
            return Err(io::Error::last_os_error())
        }

        let mut bytes_avail = 0;
        if PeekNamedPipe(
            stdin_handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut bytes_avail,
            ptr::null_mut(),
        ) == 0 {
            return Err(io::Error::last_os_error())
        }

        Ok(bytes_avail > 0)
    }
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
        println!("  {MATCH_WHOLE_WORDS}");
        println!("  {HELP}");
        return ExitCode::SUCCESS
    }

    let unicode_enabled = flag_parser.passed(&ENABLE_UNICODE);

    #[cfg(feature = "hyperscan")]
    if unicode_enabled {
        eprintln!("hyperscan does not support unicode, use `regex` feature instead");
        return ExitCode::FAILURE
    }

    if unicode_enabled && flag_parser.passed(&MATCH_WHOLE_WORDS) {
        eprintln!("you can not match whole words with unicode support enabled");
        return ExitCode::FAILURE
    }

    let stdin_is_empty = !stdin_has_data().expect("could not determine whether stdin is empty or not");

    if args.len() < 3 && (args.len() != 2 && !stdin_is_empty) {
        printdoc!(usage program);
        printdoc!(example program);
        return ExitCode::FAILURE
    }

    let Some(pattern_str) = nth_not_starting_with_dash(0, &args) else {
        printdoc!(usage program);
        printdoc!(example program);
        return ExitCode::FAILURE
    };

    if !unicode_enabled && !pattern_str.is_ascii() {
        eprintln!("if you want to match over unicode, enable unicode support with `-u` flag");
        return ExitCode::FAILURE
    }

    let search_ctx = match SearchCtx::new(&flag_parser, pattern_str) {
        Ok(ok) => ok,
        Err(e) => {
            eprintln!("could not compile {pattern_str:?}: {e}");
            return ExitCode::FAILURE
        }
    };

    if stdin_is_empty {
        let Some(dir_path) = nth_not_starting_with_dash(1, &args) else {
            return ExitCode::FAILURE
        };

        let dir = DirRec::new(dir_path);
        dir.into_iter()
            .filter_map(|e| search_ctx.filter(e))
            .filter_map(|(e, _)| {
                let file = File::open(&e).unwrap();
                let mmap = unsafe { Mmap::map(&file) }.ok()?;
                Some((e, mmap))
            }).for_each(|(e, mmap)| {
                search_ctx.search(&mmap[..], Some(e.as_path()))
            })
    } else {
        let mut content = Vec::with_capacity(512);
        if let Err(e) = io::stdin().read_to_end(&mut content) {
            eprintln!("could not read data from stdin: {e}");
            return ExitCode::FAILURE
        }

        search_ctx.search(&content, None)
    }

    ExitCode::SUCCESS
}
