use anys_cid::Cid;
use std::{env, fs};

fn main() {
    let files: Vec<String> = env::args().skip(1).collect();
    if files.is_empty() {
        eprintln!("Usage: {} <file>...", env::args().next().unwrap());
        std::process::exit(1);
    }
    for file in files {
        let mut f = fs::File::open(&file).expect("can't open file");
        let (cid, _) = Cid::from_file(Cid::VERSION_RAW, &mut f).unwrap();
        println!("{cid}");
    }
}
