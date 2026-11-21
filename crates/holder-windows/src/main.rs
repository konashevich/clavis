fn main() {
    clavis_holder::boot(true).expect("windows shell starts with the test module");
    println!("clavis-holder-windows {}", clavis_holder_windows::shell_name());
    println!("{}", clavis_protocol::PROFILE);
}