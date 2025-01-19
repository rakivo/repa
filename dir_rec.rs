// Source repository: <https://github.com/rakivo/dir_rec.rs/>

// Copyright 2024 Mark Tyrkba <marktyrkba456@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use std::fs::read_dir;
use std::path::PathBuf;
use std::collections::VecDeque;

pub struct DirRec {
    stack: VecDeque::<PathBuf>
}

impl DirRec {
    #[inline(always)]
    pub fn new<P: Into::<PathBuf>>(root: P) -> DirRec {
        DirRec {stack: vec![root.into()].into()}
    }
}

#[cfg(not(feature = "dir_rec_stop_on_error"))]
impl Iterator for DirRec {
    type Item = PathBuf;

    fn next(&mut self) -> Option::<Self::Item> {
        while let Some(p) = self.stack.pop_front() {
            if p.is_file() { return Some(p) }
            match read_dir(&p) {
                Ok(es) => es.filter_map(Result::ok).for_each(|e| {
                    self.stack.push_back(e.path())
                }),
                Err(e) => eprintln!("ERROR: {e}")
            }
        } None
    }
}

#[cfg(feature = "dir_rec_stop_on_error")]
impl Iterator for DirRec {
    type Item = std::io::Result::<PathBuf>;

    fn next(&mut self) -> Option::<Self::Item> {
        while let Some(p) = self.stack.pop_front() {
            if p.is_file() { return Some(Ok(p)) }
            match read_dir(&p) {
                Ok(es) => es.filter_map(Result::ok).for_each(|e| {
                    self.stack.push_back(e.path())
                }),
                Err(e) => return Some(Err(e))
            }
        } None
    }
}
