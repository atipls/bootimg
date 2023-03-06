use std::error::Error;
use std::path::PathBuf;
use std::ptr::hash;

use bootimg::*;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum HashType {
    #[default]
    SHA1,
    SHA256,
}

fn generate_hash_sha1(header: &BootImageHeaderV2,
                      kernel_data: &[u8],
                      ramdisk_data: &[u8],
                      second_data: &[u8],
                      dt_data: Option<&[u8]>,
                      recovery_dtbo_data: Option<&[u8]>,
                      dtb_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut hasher = sha1::Sha1::new();

    hasher.update(kernel_data);
    hasher.update(header.kernel_size.to_le_bytes());
    hasher.update(ramdisk_data);
    hasher.update(header.ramdisk_size.to_le_bytes());
    hasher.update(second_data);
    hasher.update(header.second_size.to_le_bytes());

    if let Some(dt_data) = dt_data {
        hasher.update(dt_data);
        hasher.update(header.header_version_or_dt_size.to_le_bytes());
    } else if header.header_version_or_dt_size > 0 {
        hasher.update(recovery_dtbo_data.unwrap());
        hasher.update(header.recovery_dtbo_size.to_le_bytes());

        if header.header_version_or_dt_size > 1 {
            hasher.update(dtb_data.unwrap());
            hasher.update(header.dtb_size.to_le_bytes());
        }
    }

    Ok(hasher.digest().bytes().to_vec())
}

pub fn pack(
    kernel: Option<PathBuf>,
    ramdisk: Option<PathBuf>,
    second: Option<PathBuf>,
    dt: Option<PathBuf>,
    cmdline: Option<String>,
    vendor_cmdline: Option<String>,
    base: Option<u32>,
    kernel_offset: Option<u32>,
    ramdisk_offset: Option<u32>,
    second_offset: Option<u32>,
    tags_offset: Option<u32>,
    dtb_offset: Option<u32>,
    os_version: Option<String>,
    os_patch_level: Option<String>,
    board: Option<String>,
    pagesize: Option<u32>,
    header_version: Option<u32>,
    hash_type: HashType,
    id: Option<String>,
    output: Option<PathBuf>,
    vendor_boot: Option<PathBuf>,
) -> Result<()> {
    let _ = kernel;
    let _ = ramdisk;
    let _ = second;
    let _ = dt;
    let _ = cmdline;
    let _ = vendor_cmdline;
    let _ = base;
    let _ = kernel_offset;
    let _ = ramdisk_offset;
    let _ = second_offset;
    let _ = tags_offset;
    let _ = dtb_offset;
    let _ = os_version;
    let _ = os_patch_level;
    let _ = board;
    let _ = pagesize;
    let _ = header_version;
    let _ = hash_type;
    let _ = id;
    let _ = output;
    let _ = vendor_boot;

    Ok(())
}

fn parse_os_version(version: &str) -> Result<u32> {
    let mut version = version.split('.').map(|x| x.parse::<u32>());

    let major = version.next().ok_or("Failed to get major version.")??;
    let minor = version.next().ok_or("Failed to get minor version.")??;
    let patch = version.next().ok_or("Failed to get patch version.")??;

    Ok((major << 14) | (minor << 7) | patch)
}

fn parse_os_patch_level(level: &str) -> Result<u32> {
    let mut level = level.split('-').map(|x| x.parse::<u32>());

    let year = level.next().ok_or("Failed to get year.")??;
    let month = level.next().ok_or("Failed to get month.")??;

    Ok((year << 4) | month)
}
