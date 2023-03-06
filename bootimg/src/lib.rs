pub const BOOT_MAGIC: &'static [u8; 8] = b"ANDROID!";
pub const BOOT_MAGIC_SIZE: usize = 8;
pub const BOOT_NAME_SIZE: usize = 16;
pub const BOOT_ARGS_SIZE: usize = 512;
pub const BOOT_EXTRA_ARGS_SIZE: usize = 1024;

pub const VENDOR_BOOT_MAGIC: &'static [u8; 8] = b"VNDRBOOT";
pub const VENDOR_BOOT_MAGIC_SIZE: usize = 8;
pub const VENDOR_BOOT_NAME_SIZE: usize = 16;
pub const VENDOR_BOOT_ARGS_SIZE: usize = 1024;

pub const VENDOR_RAMDISK_TYPE_NONE: u32 = 0;
pub const VENDOR_RAMDISK_TYPE_PLATFORM: u32 = 1;
pub const VENDOR_RAMDISK_TYPE_RECOVERY: u32 = 2;
pub const VENDOR_RAMDISK_TYPE_DLKM: u32 = 3;

pub const VENDOR_RAMDISK_NAME_SIZE: usize = 32;
pub const VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE: usize = 16;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootImageHeaderV0 {
    magic: [u8; BOOT_MAGIC.len()],

    kernel_size: u32,
    kernel_addr: u32,

    ramdisk_size: u32,
    ramdisk_addr: u32,

    second_size: u32,
    second_addr: u32,

    tags_addr: u32,
    page_size: u32,

    header_version_or_dt_size: u32,

    os_version: u32,

    name: [u8; BOOT_NAME_SIZE],
    cmdline: [u8; BOOT_ARGS_SIZE],

    id: [u8; 8],

    extra_cmdline: [u8; BOOT_EXTRA_ARGS_SIZE],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootImageHeaderV1 {
    magic: [u8; BOOT_MAGIC_SIZE],

    kernel_size: u32,
    kernel_addr: u32,

    ramdisk_size: u32,
    ramdisk_addr: u32,

    second_size: u32,
    second_addr: u32,

    tags_addr: u32,
    page_size: u32,

    header_version_or_dt_size: u32,

    os_version: u32,

    name: [u8; BOOT_NAME_SIZE],
    cmdline: [u8; BOOT_ARGS_SIZE],

    id: [u32; 8],

    extra_cmdline: [u8; BOOT_EXTRA_ARGS_SIZE],

    recovery_dtbo_size: u32,
    recovery_dtbo_offset: u32,

    header_size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootImageHeaderV2 {
    pub magic: [u8; BOOT_MAGIC_SIZE],

    pub kernel_size: u32,
    pub kernel_addr: u32,

    pub ramdisk_size: u32,
    pub ramdisk_addr: u32,

    pub second_size: u32,
    pub second_addr: u32,

    pub tags_addr: u32,
    pub page_size: u32,

    pub header_version_or_dt_size: u32,

    pub os_version: u32,

    pub name: [u8; BOOT_NAME_SIZE],
    pub cmdline: [u8; BOOT_ARGS_SIZE],

    pub id: [u32; 8],

    pub extra_cmdline: [u8; BOOT_EXTRA_ARGS_SIZE],

    pub recovery_dtbo_size: u32,
    pub recovery_dtbo_offset: u32,

    pub header_size: u32,

    pub dtb_size: u32,
    pub dtb_addr: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootImageHeaderV3 {
    pub magic: [u8; BOOT_MAGIC_SIZE],

    pub kernel_size: u32,
    pub ramdisk_size: u32,

    pub os_version: u32,

    pub header_size: u32,

    pub reserved: [u32; 4],

    pub header_version: u32,

    pub cmdline: [u8; BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootImageHeaderV4 {
    pub magic: [u8; BOOT_MAGIC_SIZE],

    pub kernel_size: u32,
    pub ramdisk_size: u32,

    pub os_version: u32,

    pub header_size: u32,

    pub reserved: [u32; 4],

    pub header_version: u32,

    pub cmdline: [u8; BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE],

    pub signature_size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VendorBootImageHeaderV3 {
    pub magic: [u8; VENDOR_BOOT_MAGIC_SIZE],

    pub header_version: u32,

    pub page_size: u32,

    pub kernel_addr: u32,
    pub ramdisk_addr: u32,

    pub vendor_ramdisk_size: u32,

    pub cmdline: [u8; VENDOR_BOOT_ARGS_SIZE],

    pub tags_addr: u32,
    pub name: [u8; VENDOR_BOOT_NAME_SIZE],

    pub header_size: u32,

    pub dtb_size: u32,
    pub dtb_addr: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VendorBootImageHeaderV4 {
    pub magic: [u8; VENDOR_BOOT_MAGIC_SIZE],

    pub header_version: u32,

    pub page_size: u32,

    pub kernel_addr: u32,
    pub ramdisk_addr: u32,

    pub vendor_ramdisk_size: u32,

    pub cmdline: [u8; VENDOR_BOOT_ARGS_SIZE],

    pub tags_addr: u32,
    pub name: [u8; VENDOR_BOOT_NAME_SIZE],

    pub header_size: u32,

    pub dtb_size: u32,
    pub dtb_addr: u32,

    pub vendor_ramdisk_table_size: u32,
    pub vendor_ramdisk_table_entry_count: u32,
    pub vendor_ramdisk_table_entry_size: u32,

    pub boot_config_size: u32,
}

impl std::fmt::Display for VendorBootImageHeaderV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "magic: {}\n\
             header_version: {}\n\
             page_size: {}\n\
             kernel_addr: {}\n\
             ramdisk_addr: {}\n\
             vendor_ramdisk_size: {}\n\
             cmdline: {}\n\
             tags_addr: {}\n\
             name: {}\n\
             header_size: {}\n\
             dtb_size: {}\n\
             dtb_addr: {}\n\
             vendor_ramdisk_table_size: {}\n\
             vendor_ramdisk_table_entry_count: {}\n\
             vendor_ramdisk_table_entry_size: {}\n\
             boot_config_size: {}",
            std::str::from_utf8(&self.magic).unwrap(),
            self.header_version,
            self.page_size,
            self.kernel_addr,
            self.ramdisk_addr,
            self.vendor_ramdisk_size,
            std::str::from_utf8(&self.cmdline).unwrap(),
            self.tags_addr,
            std::str::from_utf8(&self.name).unwrap(),
            self.header_size,
            self.dtb_size,
            self.dtb_addr,
            self.vendor_ramdisk_table_size,
            self.vendor_ramdisk_table_entry_count,
            self.vendor_ramdisk_table_entry_size,
            self.boot_config_size,
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VendorRamdiskTableEntry {
    pub ramdisk_size: u32,
    pub ramdisk_offset: u32,
    pub ramdisk_type: u32,
    pub ramdisk_name: [u8; VENDOR_RAMDISK_NAME_SIZE],

    pub board_id: [u8; VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE],
}
