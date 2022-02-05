use std::io;

pub fn call_with_result<F: FnOnce() -> i32>(f: F) -> Result<i32, io::Error> {
    let res = f();
    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(res)
    }
}
