#![allow(dead_code)]

use std::ffi::OsStr;
use std::os::unix::prelude::*;
use std::path::Path;

pub fn path<'a, T: Into<&'a Path>>(data: T) -> &'a [u8] {
    let data = data.into();
    let data: &OsStr = data.as_ref();
    data.as_bytes()
}

pub fn osstr<'a, T: Into<&'a OsStr>>(data: T) -> &'a [u8] {
    let data = data.into();
    data.as_bytes()
}

pub fn uri_encode<T: AsRef<[u8]>>(data: T) -> String {
    let mut buf = [0u8; 2];
    let data = data.as_ref();
    data.iter()
        .flat_map(|&c| {
            if c < b' ' || c == b'%' || c > 0x7f {
                let _ = hex::encode_to_slice(&[c] as &[u8], &mut buf);
                let mut v = "%".to_string();
                unsafe {
                    let s = std::str::from_utf8_unchecked(&buf);
                    v.push_str(s);
                };
                v.chars().collect::<Vec<char>>()
            } else {
                unsafe { String::from_utf8_unchecked(vec![c]) }
                    .chars()
                    .collect()
            }
        })
        .collect()
}

pub fn escape<T: AsRef<[u8]>>(data: T) -> String {
    let data = data.as_ref();
    if let Ok(s) = std::str::from_utf8(data) {
        return s
            .chars()
            .flat_map(|c| {
                if c < ' ' || c == '"' {
                    c.escape_default().collect::<Vec<_>>()
                } else {
                    vec![c]
                }
            })
            .collect();
    }
    let mut buf = [0u8; 2];
    data.iter()
        .flat_map(|&c| {
            if c < b' ' || c == b'"' {
                core::ascii::escape_default(c)
                    .map(|c| {
                        unsafe { String::from_utf8_unchecked(vec![c]) }
                            .chars()
                            .next()
                            .unwrap()
                    })
                    .collect::<Vec<_>>()
            } else if c > 0x7f {
                let _ = hex::encode_to_slice([c], &mut buf);
                let mut v = "\\x".to_string();
                unsafe {
                    let s = std::str::from_utf8_unchecked(&buf);
                    v.push_str(s);
                };
                v.chars().collect()
            } else {
                unsafe { String::from_utf8_unchecked(vec![c]) }
                    .chars()
                    .collect()
            }
        })
        .collect()
}
