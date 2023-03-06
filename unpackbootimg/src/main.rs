use clap::Parser;

use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    #[arg(short, long)]
    input: PathBuf,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(short, long)]
    pagesize: Option<u32>,

    #[arg(short, long, default_value = "false")]
    debug: bool,
}

fn main() {
    let arguments = Arguments::parse();

    unpackbootimg::unpack(
        arguments.input,
        arguments.output,
        arguments.pagesize,
        arguments.debug,
    )
    .unwrap();
}
