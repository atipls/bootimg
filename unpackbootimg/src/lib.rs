use std::{
    error::Error,
    ffi::CStr,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::{size_of, transmute},
    path::PathBuf,
};

use bootimg::*;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Eq, PartialEq)]
pub enum HashType {
    Sha1,
    Sha256,
}

pub fn unpack(
    input: PathBuf,
    output: Option<PathBuf>,
    pagesize: Option<u32>,
    debug: bool,
) -> Result<()> {
    let output_directory = if let Some(output) = output {
        if !output.is_dir() {
            return Err("Output is not a directory".into());
        }

        output
    } else {
        input
            .clone()
            .parent()
            .ok_or("Input has no parent")?
            .to_path_buf()
    };

    let read_padding = |file: &mut File, size: usize, pagesize: usize| -> Result<()> {
        if size & (pagesize - 1) != 0 {
            let padding = pagesize - (size & (pagesize - 1));
            file.seek(SeekFrom::Current(padding as i64))?;
        }
        Ok(())
    };

    let write_string_to_file = |name: &str, content: &str| -> Result<()> {
        let input_filename = input.file_name().unwrap().to_str().unwrap();
        let filename = output_directory.join(format!("{}-{}", input_filename, name));
        let mut file = File::create(filename)?;
        file.write_all(content.as_bytes())?;
        file.write(b"\n")?;
        Ok(())
    };

    let write_buffer_to_file =
        |file: &mut File, name: &str, size: usize, pagesize: usize| -> Result<()> {
            let input_filename = input.file_name().unwrap().to_str().unwrap();
            let filename = output_directory.join(format!("{}-{}", input_filename, name));

            let buffer = {
                let mut buffer = vec![0u8; size];
                file.read_exact(&mut buffer)?;
                read_padding(file, size, pagesize)?;
                buffer
            };

            let mut file = File::create(filename)?;
            file.write_all(&buffer)?;

            Ok(())
        };

    let mut input = File::open(input.clone())?;

    // Search the bootimg for the BOOT_MAGIC or VENDOR_BOOT_MAGIC
    let start_offset = {
        let mut chunk = [0u8; BOOT_MAGIC_SIZE];
        let mut offset = 0;
        let mut found = false;
        while !found && offset < input.metadata()?.len() {
            input.read_exact(&mut chunk)?;
            if &chunk == BOOT_MAGIC || &chunk == VENDOR_BOOT_MAGIC {
                found = true;
            } else {
                offset += 1;
                input.seek(SeekFrom::Start(offset))?;
            }
        }

        if !found {
            return Err("No boot image found".into());
        }

        offset
    };

    // Read the header
    let header: BootImageHeaderV3 = {
        let mut header = [0u8; size_of::<BootImageHeaderV3>()];
        input.seek(SeekFrom::Start(start_offset))?;
        input.read_exact(&mut header)?;

        unsafe { transmute(header) }
    };

    let magic_string = unsafe { std::str::from_utf8_unchecked(&header.magic) };
    println!("{} magic found at: {}", magic_string, start_offset);

    if &header.magic == BOOT_MAGIC {
        if header.header_version < 3 || header.header_version > 8 {
            let mut header: BootImageHeaderV2 = {
                let mut header = [0u8; size_of::<BootImageHeaderV2>()];
                input.seek(SeekFrom::Start(start_offset))?;
                input.read_exact(&mut header)?;

                unsafe { transmute(header) }
            };

            let pagesize = pagesize.unwrap_or(header.page_size);
            let base_address = header.kernel_addr - 0x00008000;

            let hash_type = detect_hash_type(&header);

            let cmdline = CStr::from_bytes_until_nul(&header.cmdline)?.to_str()?;
            let extra_cmdline = CStr::from_bytes_until_nul(&header.extra_cmdline)?.to_str()?;
            let board_name = CStr::from_bytes_until_nul(&header.name)?.to_str()?;

            println!("BOARD_KERNEL_CMDLINE {}{}", cmdline, extra_cmdline);
            println!("BOARD_KERNEL_BASE 0x{:x}", base_address);
            println!("BOARD_NAME {}", board_name);
            println!("BOARD_PAGE_SIZE {}", pagesize);
            println!(
                "BOARD_HASH_TYPE {}",
                if hash_type == HashType::Sha1 {
                    "sha1"
                } else {
                    "sha256"
                }
            );
            println!(
                "BOARD_KERNEL_OFFSET 0x{:x}",
                header.kernel_addr - base_address
            );
            println!(
                "BOARD_RAMDISK_OFFSET 0x{:x}",
                header.ramdisk_addr - base_address
            );
            println!(
                "BOARD_SECOND_OFFSET 0x{:x}",
                header.second_addr - base_address
            );
            println!("BOARD_TAGS_OFFSET 0x{:x}", header.tags_addr - base_address);
            if !print_os_version(header.os_version) {
                header.os_version = 0;
            }

            if header.header_version_or_dt_size > 0x100 {
                println!("BOARD_DT_SIZE {}", header.header_version_or_dt_size);
            } else {
                println!("BOARD_HEADER_VERSION {}", header.header_version_or_dt_size);
            }

            if header.header_version_or_dt_size <= 0x100 {
                if header.header_version_or_dt_size > 0 {
                    if header.recovery_dtbo_size != 0 {
                        println!("BOARD_RECOVERY_DTBO_SIZE {}", header.recovery_dtbo_size);
                        println!("BOARD_RECOVERY_DTBO_OFFSET {}", header.recovery_dtbo_offset);
                    }
                    println!("BOARD_HEADER_SIZE {}", header.header_size);
                } else {
                    header.recovery_dtbo_size = 0;
                }
                if header.header_version_or_dt_size > 1 {
                    if header.dtb_size != 0 {
                        println!("BOARD_DTB_SIZE {}", header.dtb_size);
                        println!("BOARD_DTB_OFFSET 0x{:x}", header.dtb_addr - base_address);
                    }
                } else {
                    header.dtb_size = 0;
                }
            }

            write_string_to_file("cmdline", format!("{}{}", cmdline, extra_cmdline).as_str())?;
            write_string_to_file("board", board_name)?;
            write_string_to_file("base", format!("0x{:x}", base_address).as_str())?;
            write_string_to_file("pagesize", format!("{}", pagesize).as_str())?;
            write_string_to_file(
                "kernel_offset",
                format!("0x{:08x}", header.kernel_addr - base_address).as_str(),
            )?;
            write_string_to_file(
                "ramdisk_offset",
                format!("0x{:08x}", header.ramdisk_addr - base_address).as_str(),
            )?;
            write_string_to_file(
                "second_offset",
                format!("0x{:08x}", header.second_addr - base_address).as_str(),
            )?;
            write_string_to_file(
                "tags_offset",
                format!("0x{:08x}", header.tags_addr - base_address).as_str(),
            )?;

            if header.os_version != 0 {
                let os_version = header.os_version >> 11;
                let os_patch_level = header.os_version & 0x7ff;

                let major = os_version >> 14 & 0x7f;
                let minor = os_version >> 7 & 0x7f;
                let patch = os_version & 0x7f;

                let year = 2000 + (os_patch_level >> 4);
                let month = os_patch_level & 0xf;

                write_string_to_file(
                    "os_version",
                    format!("{}.{}.{}", major, minor, patch).as_str(),
                )?;
                write_string_to_file("os_patch_level", format!("{}-{:02}", year, month).as_str())?;
            }

            if header.header_version_or_dt_size < 0x100 {
                write_string_to_file(
                    "header_version",
                    format!("{}\n", header.header_version_or_dt_size).as_str(),
                )?;

                if header.header_version_or_dt_size > 0 {
                    write_string_to_file(
                        "dtb_offset",
                        format!("0x{:x}", header.dtb_addr - base_address).as_str(),
                    )?;
                }
            }

            write_string_to_file(
                "hashtype",
                if hash_type == HashType::Sha1 {
                    "sha1"
                } else {
                    "sha256"
                },
            )?;

            read_padding(
                &mut input,
                size_of::<BootImageHeaderV2>() as _,
                pagesize as _,
            )?;

            write_buffer_to_file(&mut input, "kernel", header.kernel_size as _, pagesize as _)?;
            write_buffer_to_file(
                &mut input,
                "ramdisk",
                header.ramdisk_size as _,
                pagesize as _,
            )?;
            if header.second_size != 0 {
                write_buffer_to_file(&mut input, "second", header.second_size as _, pagesize as _)?;
            }

            if header.header_version_or_dt_size > 0x100 {
                write_buffer_to_file(
                    &mut input,
                    "dt",
                    header.header_version_or_dt_size as _,
                    pagesize as _,
                )?;
            } else {
                if header.recovery_dtbo_size != 0 {
                    write_buffer_to_file(
                        &mut input,
                        "recovery_dtbo",
                        header.recovery_dtbo_size as _,
                        pagesize as _,
                    )?;
                }

                if header.dtb_size != 0 {
                    write_buffer_to_file(&mut input, "dtb", header.dtb_size as _, pagesize as _)?;
                }
            }
        } else {
            let mut header: BootImageHeaderV3 = header;

            let pagesize = pagesize.unwrap_or(4096); // V3 hardcodes 4096

            let cmdline = CStr::from_bytes_until_nul(&header.cmdline)?.to_str()?;

            println!("BOARD_KERNEL_CMDLINE {}", cmdline);
            println!("BOARD_PAGE_SIZE {}", pagesize);
            print_os_version(header.os_version);

            println!("BOARD_HEADER_VERSION {}", header.header_version);
            println!("BOARD_HEADER_SIZE {}", header.header_size);

            write_string_to_file("cmdline", cmdline)?;

            let os_version = header.os_version >> 11;
            let os_patch_level = header.os_version & 0x7ff;

            let major = os_version >> 14 & 0x7f;
            let minor = os_version >> 7 & 0x7f;
            let patch = os_version & 0x7f;

            let year = 2000 + (os_patch_level >> 4);
            let month = os_patch_level & 0xf;

            write_string_to_file(
                "os_version",
                format!("{}.{}.{}", major, minor, patch).as_str(),
            )?;
            write_string_to_file("os_patch_level", format!("{}-{:02}", year, month).as_str())?;

            write_string_to_file(
                "header_version",
                format!("{}\n", header.header_version).as_str(),
            )?;
        }
    } else {
        let mut header: VendorBootImageHeaderV3 = {
            let mut header = [0u8; size_of::<VendorBootImageHeaderV3>()];
            input.seek(SeekFrom::Start(start_offset))?;
            input.read_exact(&mut header)?;

            unsafe { transmute(header) }
        };

        let pagesize = pagesize.unwrap_or(header.page_size);
        let base_address = header.kernel_addr - 0x00008000;

        let cmdline = CStr::from_bytes_until_nul(&header.cmdline)?.to_str()?;
        let name = CStr::from_bytes_until_nul(&header.name)?.to_str()?;

        println!("BOARD_VENDOR_CMDLINE {}", cmdline);
        println!("BOARD_VENDOR_BASE 0x{:08x}", base_address);
        println!("BOARD_NAME {}", name);
        println!("BOARD_PAGE_SIZE {}", header.page_size);
        println!(
            "BOARD_KERNEL_OFFSET 0x{:08x}",
            header.kernel_addr - base_address
        );
        println!(
            "BOARD_RAMDISK_OFFSET 0x{:08x}",
            header.ramdisk_addr - base_address
        );
        println!(
            "BOARD_TAGS_OFFSET 0x{:08x}",
            header.tags_addr - base_address
        );
        println!("BOARD_HEADER_VERSION {}", header.header_version);
        println!("BOARD_HEADER_SIZE {}", header.header_size);
        println!("BOARD_DTB_SIZE {}", header.dtb_size);
        println!("BOARD_DTB_OFFSET 0x{:08x}", header.dtb_addr - base_address);

        write_string_to_file("vendor_cmdline", cmdline)?;
        write_string_to_file("board", name)?;
        write_string_to_file("base", format!("0x{:08x}", base_address).as_str())?;
        write_string_to_file("pagesize", format!("{}", pagesize).as_str())?;
        write_string_to_file(
            "kernel_offset",
            format!("0x{:08x}", header.kernel_addr - base_address).as_str(),
        )?;
        write_string_to_file(
            "ramdisk_offset",
            format!("0x{:08x}", header.ramdisk_addr - base_address).as_str(),
        )?;
        write_string_to_file(
            "tags_offset",
            format!("0x{:08x}", header.tags_addr - base_address).as_str(),
        )?;
        write_string_to_file(
            "header_version",
            format!("{}\n", header.header_version).as_str(),
        )?;
        write_string_to_file(
            "dtb_offset",
            format!("0x{:08x}", header.dtb_addr - base_address).as_str(),
        )?;

        read_padding(
            &mut input,
            size_of::<VendorBootImageHeaderV3>(),
            pagesize as _,
        )?;

        write_buffer_to_file(
            &mut input,
            "vendor_ramdisk",
            header.vendor_ramdisk_size as _,
            pagesize as _,
        )?;
        write_buffer_to_file(&mut input, "dtb", header.dtb_size as _, pagesize as _)?;
    }

    Ok(())
}

fn detect_hash_type(header: &BootImageHeaderV2) -> HashType {
    let maybe_hash = header.id.as_ptr() as *const u8;

    for i in 24..32 {
        if unsafe { *maybe_hash.offset(i) } != 0 {
            return HashType::Sha256;
        }
    }

    return HashType::Sha1;
}

fn print_os_version(os_version_header: u32) -> bool {
    if os_version_header == 0 {
        return false;
    }

    let os_version = os_version_header >> 11;
    let os_patch_level = os_version_header & 0x7ff;

    let major = os_version >> 14 & 0x7f;
    let minor = os_version >> 7 & 0x7f;
    let patch = os_version & 0x7f;

    let year = 2000 + (os_patch_level >> 4);
    let month = os_patch_level & 0xf;

    if major < 128
        && minor < 128
        && patch < 128
        && year >= 2000
        && year < 2128
        && month >= 1
        && month <= 12
    {
        println!("BOARD_OS_VERSION {}.{}.{}", major, minor, patch);
        println!("BOARD_OS_PATCH_LEVEL {}-{:02}", year, month);
        true
    } else {
        false
    }
}
