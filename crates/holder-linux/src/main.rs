fn main() {
    clavis_holder_linux::boot().expect("linux shell starts with the test module");
    println!("clavis-holder {}", clavis_protocol::PROFILE);
}
