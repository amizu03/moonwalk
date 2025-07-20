use crate::{analyze::AnalyzedBin, pdb::Symbols, prelude::*};

use pe_parser::{pe::PortableExecutable, section::SectionHeader};
use std::{collections::HashMap, fs::File, sync::Arc};

#[derive(Debug, Default, Copy, Clone, PartialEq)]
#[repr(C)]
pub struct RuntimeFunction {
    pub fn_start: u32,
    pub fn_end: u32,
    pub unwind_info: u32,
}

const_assert_eq!(size_of::<RuntimeFunction>(), 0xC);

const UNW_FLAG_CHAININFO: u8 = 0x4;

#[optimize(speed)]
fn calc_frame_size(
    module: usize,
    runtime_function: *const RuntimeFunction,
    ignore_sp_and_bp: bool,
    base_pointer: &mut bool,
) -> usize {
    let unwind_info = (module + (unsafe { *runtime_function }).unwind_info as usize) as *mut u8;
    let version_and_flags = unwind_info;

    // We don't care about the version, we just need the flags to check if there is an Unwind Chain.
    let flags = unsafe { version_and_flags.read_unaligned() } & 0b11111;
    let unwind_codes_count = unsafe { *(unwind_info.add(2)) };

    // We skip 4 bytes corresponding to Version + flags, Size of prolog, Count of unwind codes
    // and Frame Register + Frame Register offset.
    // This way we reach the Unwind codes array.
    let mut unwind_code = (unsafe { unwind_info.add(4) }) as *mut u8;
    let mut unwind_code_operation_code_info = unsafe { unwind_code.add(1) };

    // This counter stores the size of the stack frame in bytes.
    let mut frame_size = 0;
    let mut index = 0;

    while index < unwind_codes_count {
        let operation_code_and_info = unwind_code_operation_code_info;

        let operation_code = unsafe { operation_code_and_info.read_unaligned() } & 0xF; // operation info
        let operation_info = (unsafe { operation_code_and_info.read_unaligned() } >> 4) & 0xF; // operation code

        match operation_code {
            0 => {
                // UWOP_PUSH_NONVOL

                // operation_info == 4 -> RSP
                if operation_code == 4 && !ignore_sp_and_bp {
                    return 0;
                }

                frame_size += 8;
            }
            1 => {
                // UWOP_ALLOC_LARGE
                if operation_info == 0 {
                    let size = unsafe { *(unwind_code_operation_code_info.add(1) as *mut i16) };
                    frame_size += size as isize * 8;

                    unwind_code = unsafe { unwind_code.add(2) };
                    index += 1;
                } else if operation_info == 1 {
                    let size =
                        unsafe { *(unwind_code_operation_code_info.add(1) as *mut u16) } as i32;
                    let size2 = (unsafe { *(unwind_code_operation_code_info.add(3) as *mut u16) }
                        as i32)
                        << 16;
                    frame_size += size as isize + size2 as isize;

                    unwind_code = unsafe { unwind_code.add(4) };
                    index += 2;
                }
            }
            2 => {
                // UWOP_ALLOC_SMALL
                frame_size += (operation_info * 8 + 8) as isize;
            }
            3 => {
                // UWOP_SET_FPREG // Dynamic alloc "does not change" frame's size
                *base_pointer = true; // This is not used atm
                if !ignore_sp_and_bp {
                    return 0; // This is meant to prevent the use of return addresses corresponding to functions that set a base pointer
                }
            }
            4 => {
                // UWOP_SAVE_NONVOL
                // operation_info == 4 -> RSP
                if operation_info == 4 && !ignore_sp_and_bp {
                    return 0;
                }

                unwind_code = unsafe { unwind_code.add(2) };
                index += 1;
            }
            5 => {
                // UWOP_SAVE_NONVOL_FAR
                // operation_info == 4 -> RSP
                if operation_info == 4 && !ignore_sp_and_bp {
                    return 0;
                }

                unwind_code = unsafe { unwind_code.add(4) };
                index += 2;
            }
            8 => {
                // UWOP_SAVE_XMM128
                unwind_code = unsafe { unwind_code.add(2) };
                index += 1;
            }
            9 => {
                // UWOP_SAVE_XMM128_FAR
                unwind_code = unsafe { unwind_code.add(4) };
                index += 2;
            }
            10 => {
                // UWOP_PUSH_MACH_FRAME
                if operation_info == 0 {
                    frame_size += 0x40;
                } else if operation_code == 1 {
                    frame_size += 0x48;
                }
            }
            _ => {}
        }

        unwind_code = unsafe { unwind_code.add(2) };
        unwind_code_operation_code_info = unsafe { unwind_code.add(1) };
        index += 1;
    }

    // In case that the flag UNW_FLAG_CHAININFO is set, we recursively call this function.
    if (flags & UNW_FLAG_CHAININFO) != 0 {
        if unwind_codes_count % 2 != 0 {
            unwind_code = unsafe { unwind_code.add(2) };
        }

        let result = calc_frame_size(module, unwind_code as _, ignore_sp_and_bp, base_pointer);

        frame_size += result as isize;
    }

    frame_size as usize
}

pub struct Bin {
    pub data: Vec<u8>,
    pub pe: PortableExecutable,
    // FUNCTION => STACK SIZE
    pub rtt: Vec<(RuntimeFunction, usize)>,
    pub symbols: Symbols,
    // RVA => SIZE
    // pub data_refs: HashMap<usize, usize>,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ImageDebugDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub typ: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

impl Bin {
    pub fn read_rva<T>(&self, va: usize) -> T {
        unsafe {
            (self.data.as_ptr() as *const T)
                .byte_add(self.rva_to_file_offset(va).0)
                .read_unaligned()
        }
    }

    pub fn read_bytes<'a>(&'a self, va: usize) -> &'a [u8] {
        let (offset, s) = self.rva_to_file_offset(va);
        let cb = (offset - s.pointer_to_raw_data as usize);
        let cb_remaining = s.size_of_raw_data as usize - cb;

        &self.data[offset..offset + cb_remaining]
    }

    pub fn rva_to_file_offset<'a>(&'a self, va: usize) -> (usize, &'a SectionHeader) {
        let s = self
            .pe
            .section_table
            .iter()
            .find(|s| {
                (s.virtual_address as usize..(s.virtual_address + s.virtual_size) as usize)
                    .contains(&va)
            })
            .unwrap();

        (
            s.pointer_to_raw_data as usize + (va - s.virtual_address as usize),
            s,
        )
    }

    pub fn load(path: &str) -> Result<Self> {
        let mut path_no_file = path;
        if let Some(last_path_pos) = path.rfind(|c| c == '/') {
            path_no_file = &path[..last_path_pos];
        }

        let mut path_no_file = path_no_file.to_owned();
        path_no_file.push('/');

        let data = std::fs::read(path).map_err(|_| Error::ReadFile)?;
        let pe = pe_parser::pe::parse_portable_executable(&data).map_err(|_| Error::ParsePE)?;

        let rdata = pe
            .section_table
            .iter()
            .find(|s| s.name.starts_with(b".rdata"))
            .unwrap();
        let ex = pe.section_table[3];
        let ex_section_raw_data =
            data.as_ptr().addr() + (ex.virtual_address - ex.pointer_to_raw_data) as usize;

        // first pass find functions by runtime table
        let mut rtt = unsafe {
            slice::from_raw_parts(
                data.as_ptr().byte_add(ex.pointer_to_raw_data as usize) as *const RuntimeFunction,
                ex.virtual_size.min(ex.size_of_raw_data) as usize / size_of::<RuntimeFunction>(),
            )
            .iter()
            .map(|rt| {
                (
                    *rt,
                    calc_frame_size(
                        data.as_ptr() as usize
                            - (rdata.virtual_address - rdata.pointer_to_raw_data) as usize,
                        rt,
                        false,
                        &mut false,
                    ),
                )
            })
            .collect::<Vec<_>>()
        };

        // sort by function address in ascending order
        rtt.sort_by_key(|x| x.0.fn_start);

        // second pass find hidden functions by searching for unchecked code
        let code_start = pe.optional_header_64.unwrap().base_of_code as usize;

        let opt_hdr = pe.optional_header_64.unwrap();

        let mut x = Self {
            data,
            pe,
            rtt,
            symbols: Symbols::default(),
        };

        let debug_dir = opt_hdr.data_directories.debug;
        let dbg = x.read_rva::<ImageDebugDirectory>(debug_dir.virtual_address as usize);

        if dbg.typ != 2 {
            println!("no debug info!");
        }

        let cv_info = x.read_bytes(dbg.address_of_raw_data as usize);

        // pdb codeview struct starts with RSDS signature
        if &cv_info[0..4] != b"RSDS" {
            println!("bad pdb signature!");
        }

        let pdb_path_offset = 24; // GUID (16) + Age (4) + "RSDS" (4)
        let mut end = pdb_path_offset;

        while end < cv_info.len() && cv_info[end] != 0 {
            end += 1;
        }

        let pdb_path = core::str::from_utf8(&cv_info[pdb_path_offset..end]).unwrap();

        path_no_file.push_str(&pdb_path);

        let syms = Symbols::from_file(File::open(path_no_file).map_err(|_| Error::ReadFile)?);

        x.symbols = syms;

        let mut hidden_code = Vec::<(RuntimeFunction, usize)>::new();

        let code = x.read_bytes(code_start);

        let mut rt = x.rtt.iter();
        let mut prev = 0x0;

        while let Some((rt, _frame_size)) = rt.next() {
            while prev < rt.fn_start as usize - code_start {
                let mut found = false;

                let start = prev;

                for i in prev..(rt.fn_start as usize - code_start) {
                    if code[i] == 0xC3 && matches!(code.get(i + 1), Some(0x90) | Some(0xCC)) {
                        prev = i + 0x1;
                        found = true;

                        hidden_code.push((
                            RuntimeFunction {
                                fn_start: (code_start + start) as u32,
                                fn_end: (code_start + prev) as u32,
                                unwind_info: 0x0,
                            },
                            0,
                        ));

                        if code[i + 1] == 0x90 {
                            prev += 1;
                        }

                        break;
                    } else if (code[i] == 0xFF
                        && matches!(code.get(i + 1), Some(0x25))
                        && matches!(code.get(i + 6), Some(0xCC)))
                    {
                        prev = i + 0x6;
                        found = true;

                        hidden_code.push((
                            RuntimeFunction {
                                fn_start: (code_start + start) as u32,
                                fn_end: (code_start + prev) as u32,
                                unwind_info: 0x0,
                            },
                            0,
                        ));

                        break;
                    }
                }

                if !found {
                    prev = rt.fn_end as usize - code_start;
                }
            }
        }

        // sort by function address in ascending order
        x.rtt.append(&mut hidden_code);
        x.rtt.sort_by_key(|x| x.0.fn_start);

        Ok(x)
    }

    pub fn analyze(self) -> AnalyzedBin {
        // println!("Bin::analyze(self)");

        AnalyzedBin::analyze_bin(Arc::new(self))
    }
}
