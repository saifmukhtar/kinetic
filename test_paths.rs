use service_manager::*;
use std::env;

fn main() {
    let manager = <dyn ServiceManager>::native().unwrap();
    println!("Manager paths:");
    // wait, we can't easily inspect internal paths without the types.
}
