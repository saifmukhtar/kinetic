use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(transparent)]
struct UTime(u64);

#[derive(Serialize)]
struct Doc {
    time: UTime,
}

fn main() {
    let doc = Doc { time: UTime(100) };
    println!("{}", serde_jcs::to_string(&doc).unwrap());
}
