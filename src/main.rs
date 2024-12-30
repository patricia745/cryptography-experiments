mod sha;

use std::io::{self, Write};

fn main() {
    loop {
        print!("Enter your command: ");
        
        let mut line = String::new();
        io::stdout().flush().unwrap();
        
        io::stdin().read_line(&mut line).unwrap();
        let line = line.trim();
        let args: Vec<&str> = line.split_whitespace().collect();
        
        match args.as_slice() {
            ["sha256", input_data] => {
                if input_data.starts_with('"') && input_data.ends_with('"') {
                    let result = sha::sha256(&input_data[1..input_data.len() - 1]);
                    println!("Digest: {}", result);
                }
                
            },
            ["exit"] => {
                break;
            }
            _ => {
                println!("Unsupported algorithm:");
            }
        } 
    }
}
