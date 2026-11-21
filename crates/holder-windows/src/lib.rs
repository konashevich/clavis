pub fn shell_name() -> &'static str {
    "windows"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_is_windows() {
        assert_eq!(shell_name(), "windows");
    }
}