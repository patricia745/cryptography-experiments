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
            ["hash"] => {
                println!("Selected hash operation");
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
