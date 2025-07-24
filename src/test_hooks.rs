// Test file to verify hooks are working
pub fn test_formatting()  {
    let x=5;let y=10;
    println!("Bad formatting: {}", x+y);
}

pub fn test_clippy_warning() {
    let result: Result<i32, &str> = Ok(42);
    let value = result.unwrap(); // This should trigger clippy warning
    println!("Value: {}", value);
}