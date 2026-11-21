fn main() {
    clavis_holder::boot(true).expect("linux shell starts with the test module");
    println!("clavis-holder {}", clavis_protocol::PROFILE);
}