#![feature(optimize_attribute, vec_pop_if, let_chains, unsigned_signed_diff)]
#![allow(unused_variables, dead_code, warnings)]

mod analyze;
mod bin;
mod error;
mod function;
mod mapper;
mod obfuscator;
mod pdb;
mod prelude;

use std::{arch::x86_64::_rdtsc, collections::HashMap, fs::File};

use function::{align_up, decode_single_instruction, fmt_flags};
use iced_x86::{Decoder, DecoderOptions, code_asm::CodeAssembler};
use memflow::{mem::MemoryView, plugins::Inventory};
use obfuscator::ObfuscatorConfig;
use pe_parser::{pe::parse_portable_executable, section::SectionFlags};

use crate::prelude::*;

// const MAGIC: u64 = 0x890123719478141;

fn main() -> Result<()> {
    // let mut analyzed = Bin::load("input/lotus_kmd.dll")?.analyze();
    // // let mut analyzed = Bin::load("input/test_sys.dll")?.analyze();

    // let mut asm = CodeAssembler::new(64).unwrap();

    // let (mut out, mut data, (oep, mut oep_out), data_offset) = Obfuscator::new(0x0).scatter(
    //     &analyzed,
    //     &[],
    //     &ObfuscatorConfig {
    //         shx: false,
    //         xor: false,
    //         mov: false,
    //         encrypt_oep: true,
    //         swap: true,
    //     },
    //     0x1000,
    // )?;

    // out.resize(align_up(out.len(), 0x1000), 0);

    // out.append(&mut data);

    // out.resize(align_up(out.len(), 0x1000), 0);

    // oep_out.resize(align_up(oep_out.len(), 0x1000), 0);

    // std::fs::write("input/lotus_kmd.bin", &out);
    // std::fs::write("input/lotus_kmd.oep.bin", &oep_out);

    // return Ok(());

    // let bin = std::fs::read("input/lotus_kmd.dll").unwrap();
    let bin = std::fs::read("input/hv.dll").unwrap();
    let pe = parse_portable_executable(&bin).unwrap();
    let optional = pe.optional_header_64.unwrap();
    let size_of_image = optional.size_of_image as usize;
    let size_of_image = ((size_of_image + 0xFFF) >> 12 << 12) - 0x1000;
    // let size_of_image = 0x10000;

    println!("size: 0x{size_of_image:X}");

    let mm_free_independent_pages= mapper::find_pattern(
        "ntoskrnl.exe",
        // "PAGE",
        ".text",
        // b"\x48\x89\x5C\x24\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8B\xEC\x48\x83\xEC\x60\x48\x83\x65\xD0\x00\xBE\x00\x00\x00\x00",
        b"\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8B\xEC\x48\x83\xEC\x60\x33\xC0\x0F\x57\xC0",
    );
    let mm_set_page_protection = mapper::find_pattern(
        "ntoskrnl.exe",
        ".text",
        // b"\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x56\x41\x57\x48\x81\xEC\x00\x01\x00\x00\x48\x8B\x05",
        b"\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20\x41\x8B\xF8\x48\x8B\xF2\x48\x8B\xD9"
    );
    let mm_allocate_independent_pages_ex = mapper::find_pattern("ntoskrnl.exe", "PAGE",

        // b"\x48\x8B\xC4\x48\x89\x58\x10\x44\x89\x48\x20\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xEC"
        b"\x48\x89\x5C\x24\x10\x44\x89\x4C\x24\x20\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x60\x48\xF7\xC1\xFF\x0F\x00\x00"
    );

    let oep_code = mapper::call_func(mm_allocate_independent_pages_ex, [0x2000, usize::MAX, 0, 0]);
    mapper::call_func(mm_set_page_protection, [oep_code, 0x2000, 0x40, 0]);

    // println!("{oep_code:X}");

    let code = mapper::call_func(
        mm_allocate_independent_pages_ex,
        [size_of_image, usize::MAX, 0, 0],
    );
    mapper::call_func(mm_set_page_protection, [code, size_of_image, 0x40, 0]);

    // println!("{code:X}");

    let rel32_from_oep = ((code as isize) - (oep_code as isize)) as i32;

    let maybe_memory = std::fs::read_to_string("code_area.txt")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let oep = std::fs::read_to_string("oep.txt")
        .unwrap()
        .parse::<usize>()
        .unwrap();

    // let inventory = Inventory::scan();
    // let conn = inventory.builder().connector("qemu");
    // let mut os = conn
    //     .os("win32")
    //     .build()
    //     .expect("Failed to build OS connector");

    // let mut mem = os.cast_impl_memoryview().unwrap();

    // if matches!(mem.read(maybe_memory.into()), Ok(MAGIC)) {
    //     // mapper::call_func(oep.into(), [0; 4]);
    //     println!("Unloaded.");
    //     return Ok(());
    // }

    // mapper::call_user_func("user32.dll", "RealMsgWaitForMultipleObjectsEx", [0; 4]);
    // mapper::call_user_func("win32u.dll", "NtUserMsgWaitForMultipleObjectsEx", [0; 4]);
    // mapper::call_user_func("win32u.dll", "NtUserMsgWaitForMultipleObjectsEx", [0; 6]);

    use bin::Bin;
    use obfuscator::Obfuscator;

    let mut analyzed = Bin::load("input/hv.dll")?.analyze();
    // let mut analyzed = Bin::load("input/test_sys.dll")?.analyze();

    println!("{:#X?}", analyzed.bin.rtt);

    let mut asm = CodeAssembler::new(64).unwrap();

    let (mut out, mut data, (oep, mut oep_out), data_offset) = Obfuscator::new(0x0).scatter(
        &analyzed,
        &[],
        &ObfuscatorConfig {
            shx: false,
            xor: false,
            mov: false,
            encrypt_oep: true,
            swap: false,
        },
        rel32_from_oep,
    )?;

    out.resize(align_up(out.len(), 0x1000), 0);

    out.append(&mut data);

    out.resize(align_up(out.len(), 0x1000), 0);

    let oep_out_len = oep_out.len();
    oep_out.resize(align_up(oep_out.len(), 0x1000), 0);

    std::fs::write("input/lotus_kmd.bin", &out);
    std::fs::write("input/lotus_kmd.oep.bin", &oep_out);

    println!("alloc: {code:X}");

    let inventory = Inventory::scan();
    let conn = inventory.builder().connector("qemu");
    let mut os = conn
        .os("win32")
        .build()
        .expect("Failed to build OS connector");
    let mut mem = os.cast_impl_memoryview().unwrap();

    // copy magic number so we can find this memory later
    // mem.write(code.into(), &MAGIC).unwrap();

    // encrypt entry point
    // jmp no_nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // nop
    // no_nop:
    // vmovdqa ymm0, [rip-0x8-0x2-0xE]
    // vxorps ymm0,ymm0, [rip+0x123]
    // println!("{:X}", oep_out_len);
    // for i in (0..(oep_out_len - 32)).step_by(32) {
    //     let mut bytes: [u8; 32] = [
    //         0xEB, 0x0E, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    //         0x90, 0x90, 0xC5, 0xFD, 0x6F, 0x05, 0xE8, 0xFF, 0xFF, 0xFF, 0xC5, 0xFC, 0x57, 0x05,
    //         0x23, 0x01, 0x00, 0x00,
    //     ];

    //     let mut ip = i + 0x0;
    //     let mut key_ip = i + 0x1000;

    //     for b in &mut bytes[0x2..=0xF] {
    //         *b = unsafe { _rdtsc().unchecked_mul(38127) } as u8;
    //     }
    //     let rel32 = ((ip as isize + 0x20) - key_ip as isize) as i32;
    //     bytes[0x18 + 0x4..].copy_from_slice(&rel32.to_le_bytes());

    //     let mut key = [0u8; 32];

    //     for j in 0..32 {
    //         key[j] = bytes[j] ^ oep_out[i + j];
    //     }

    //     mem.write_raw((oep_code + ip).into(), &bytes).unwrap();
    //     mem.write_raw((oep_code + key_ip).into(), &key).unwrap();
    // }

    // let mut bytes = [0xE9, 0x00, 0x00, 0x00, 0x00];
    // let dst = oep;
    // let src = oep_out_len - 0x20 + 0x5;
    // let rel32 = (dst as isize - src as isize) as i32;
    // bytes[0x1..].copy_from_slice(&rel32.to_le_bytes());
    // mem.write_raw((oep_code + oep_out_len - 0x20).into(), &bytes)
    //     .unwrap();

    // copy image
    mem.write_raw(oep_code.into(), &oep_out).unwrap();
    mem.write_raw(code.into(), &out).unwrap();

    // copy image
    // let oep = oep_code;
    let oep = oep_code + oep;

    println!("OEP: {:X}", oep);

    // return Ok(());

    mapper::call_func(oep.into(), [code, out.len(), 0, 0]);

    // zero and free OEP
    oep_out.fill(0);
    mem.write_raw(oep_code.into(), &oep_out).unwrap();
    let oep_code = mapper::call_func(mm_free_independent_pages, [oep_code, 0x2000, 0, 0]);

    println!("Freed OEP.");

    std::fs::write("code_area.txt", code.to_string()).unwrap();
    std::fs::write("oep.txt", oep.to_string()).unwrap();

    return Ok(());

    let bin = std::fs::read("input/hv.dll").unwrap();
    let pe = parse_portable_executable(&bin).unwrap();
    let optional = pe.optional_header_64.unwrap();
    let size_of_image = optional.size_of_image as usize;
    // let size_of_image = out.len();
    let size_of_image = ((size_of_image + 0xFFF) >> 12 << 12) - 0x1000;

    println!("size: 0x{size_of_image:X}");

    // let ex_alloc_pool = mapper::get_proc_addr("ntoskrnl.exe", "ExAllocatePool2");
    let mm_set_page_protection = mapper::find_pattern(
        "ntoskrnl.exe",
        ".text",
        b"\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x56\x41\x57\x48\x81\xEC\x00\x01\x00\x00\x48\x8B\x05",
    );
    let mm_allocate_independent_pages_ex = mapper::find_pattern("ntoskrnl.exe", "PAGE", b"\x48\x8B\xC4\x48\x89\x58\x10\x44\x89\x48\x20\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xEC");
    let code = mapper::call_func(
        mm_allocate_independent_pages_ex,
        // ex_alloc_pool,
        [size_of_image, usize::MAX, 0, 0],
        // [0x80, size_of_image, 0x656E6F4E, 0],
    );
    mapper::call_func(mm_set_page_protection, [code, size_of_image, 0x40, 0]);

    println!("alloc: {code:X}");

    let inventory = Inventory::scan();
    let conn = inventory.builder().connector("qemu");
    let mut os = conn
        .os("win32")
        .build()
        .expect("Failed to build OS connector");
    let mut mem = os.cast_impl_memoryview().unwrap();

    // copy image headers
    // mem.write_raw(code.into(), &bin[..optional.size_of_headers as usize])
    //     .unwrap();

    // copy sections
    for s in pe.section_table {
        if let Some(c) = s.get_characteristics() {
            if c.contains(SectionFlags::IMAGE_SCN_CNT_UNINITALIZED_DATA) {
                continue;
            }

            let addr = code + s.virtual_address as usize - 0x1000;

            mem.write_raw(
                addr.into(),
                &bin[s.pointer_to_raw_data as usize
                    ..((s.pointer_to_raw_data + s.size_of_raw_data) as usize)],
            )
            .unwrap();

            // let prot = if c.contains(SectionFlags::IMAGE_SCN_MEM_EXECUTE) {
            //     if c.contains(SectionFlags::IMAGE_SCN_MEM_WRITE) {
            //         0x40
            //     } else {
            //         0x20
            //     }
            // } else if c.contains(SectionFlags::IMAGE_SCN_MEM_WRITE) {
            //     0x04
            // } else if c.contains(SectionFlags::IMAGE_SCN_MEM_READ) {
            //     0x02
            // } else {
            //     0x01
            // };

            // mapper::call_func(
            //     mm_set_page_protection,
            //     [addr, s.virtual_size as usize, prot, 0],
            // );
        }
    }

    // copy image
    let oep = code + optional.address_of_entry_point as usize - 0x1000;

    println!("OEP: {:X}", oep);

    // std::io::stdin().read_line(&mut String::new());

    mapper::call_func(oep.into(), [code, size_of_image, 0, 0]);

    // mem.write_raw(code.into(), &out).unwrap();
    // mem.write_raw((code + data_offset).into(), &data).unwrap();

    // mapper::call_func(code + oep, [0; 4]);

    // println!("scattered!");

    // println!("OEP: {:X}", code + oep);

    // std::io::stdin().read_line(&mut String::new());

    // mapper::call_func((code + oep).into(), [0, 0, 0, 0]);

    // println!("called!");

    // 0x1000 * 1

    // std::fs::write("input/lotus_kmd.bin", out).unwrap();

    Ok(())
}
