use clap::{arg, Parser, ValueEnum};

use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, ValueEnum)]
#[clap(rename_all = "kebab_case")]
enum HashTypeArg {
    #[default]
    SHA1,
    SHA256,
}

impl Into<mkbootimg::HashType> for HashTypeArg {
    fn into(self) -> mkbootimg::HashType {
        match self {
            HashTypeArg::SHA1 => mkbootimg::HashType::SHA1,
            HashTypeArg::SHA256 => mkbootimg::HashType::SHA256,
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    #[arg(long)]
    kernel: Option<PathBuf>,

    #[arg(long)]
    ramdisk: Option<PathBuf>,

    #[arg(long)]
    vendor_ramdisk: Option<PathBuf>,

    #[arg(long)]
    second: Option<PathBuf>,

    #[arg(long)]
    dtb: Option<PathBuf>,

    #[arg(long)]
    recovery_dtbo: Option<PathBuf>,

    #[arg(long)]
    recovery_acpio: Option<PathBuf>,

    #[arg(long)]
    dt: Option<PathBuf>,

    #[arg(long)]
    cmdline: Option<String>,

    #[arg(long)]
    vendor_cmdline: Option<String>,

    #[arg(long)]
    base: Option<u32>,

    #[arg(long)]
    kernel_offset: Option<u32>,

    #[arg(long)]
    ramdisk_offset: Option<u32>,

    #[arg(long)]
    second_offset: Option<u32>,

    #[arg(long)]
    tags_offset: Option<u32>,

    #[arg(long)]
    dtb_offset: Option<u32>,

    #[arg(long)]
    os_version: Option<String>,

    #[arg(long)]
    os_patch_level: Option<String>,

    #[arg(long)]
    board: Option<String>,

    #[arg(long)]
    pagesize: Option<u32>,

    #[arg(long)]
    header_version: Option<u32>,

    #[arg(long, value_enum)]
    hash_type: Option<HashTypeArg>,

    #[arg(long)]
    id: Option<String>,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long)]
    vendor_boot: Option<PathBuf>,
}

fn main() {
    let arguments = Arguments::parse();

    mkbootimg::pack(
        arguments.kernel,
        arguments.ramdisk,
        arguments.second,
        arguments.dt,
        arguments.cmdline,
        arguments.vendor_cmdline,
        arguments.base,
        arguments.kernel_offset,
        arguments.ramdisk_offset,
        arguments.second_offset,
        arguments.tags_offset,
        arguments.dtb_offset,
        arguments.os_version,
        arguments.os_patch_level,
        arguments.board,
        arguments.pagesize,
        arguments.header_version,
        arguments.hash_type.unwrap_or_default().into(),
        arguments.id,
        arguments.output,
        arguments.vendor_boot,
    )
    .unwrap();
}
