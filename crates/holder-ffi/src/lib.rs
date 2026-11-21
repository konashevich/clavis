use jni::objects::{JByteArray, JClass};
use jni::sys::jint;
use jni::JNIEnv;

pub fn profile() -> &'static str {
    clavis_protocol::PROFILE
}

#[no_mangle]
pub extern "C" fn clavis_profile(out: *mut u8, cap: usize) -> i32 {
    if out.is_null() {
        return -1;
    }
    let bytes = profile().as_bytes();
    let n = bytes.len().min(cap);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, n);
    }
    n as i32
}

#[no_mangle]
pub extern "system" fn Java_clavis_holder_Core_profile(
    env: JNIEnv,
    _class: JClass,
    buffer: JByteArray,
) -> jint {
    let bytes = profile().as_bytes();
    let len = match env.get_array_length(&buffer) {
        Ok(len) => len as usize,
        Err(_) => return -1,
    };
    let n = bytes.len().min(len);
    let signed: Vec<i8> = bytes[..n].iter().map(|byte| *byte as i8).collect();
    if env.set_byte_array_region(&buffer, 0, &signed).is_err() {
        return -1;
    }
    n as jint
}

#[cfg(test)]
mod tests {
    #[test]
    fn profile_matches_protocol() {
        assert_eq!(super::profile(), clavis_protocol::PROFILE);
    }

    #[test]
    fn c_profile_writes_bytes() {
        let mut buffer = [0u8; 128];
        let count = super::clavis_profile(buffer.as_mut_ptr(), buffer.len());
        let count = count as usize;
        assert_eq!(&buffer[..count], super::profile().as_bytes());
    }
}