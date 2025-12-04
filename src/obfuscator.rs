use std::{collections::HashMap, time::Instant};

use crate::{
    analyze::AnalyzedBin,
    bin::Bin,
    function::{BranchBlock, align_up},
    prelude::*,
};

#[derive(Debug, Default, Copy, Clone)]
pub struct Obfuscator {
    pub seed: u64,
}

#[derive(Debug, Default, Copy, Clone)]
pub struct ObfuscatorConfig {
    pub shx: bool,
    pub xor: bool,
    pub mov: bool,
    pub swap: bool,
    pub encrypt_oep: bool,
}

impl Obfuscator {
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    pub fn scatter(
        &self,
        bin: &AnalyzedBin,
        rvas: &[usize],
        config: &ObfuscatorConfig,
        oep_page_offset: i32,
    ) -> Result<(Vec<u8>, Vec<u8>, (usize, Vec<u8>), usize)> {
        let mut start_time = Instant::now();

        let mut data_out = Vec::new();
        let mut data: HashMap<usize, usize> = HashMap::new();
        let mut oep_out = vec![0x00u8; 0x1000];
        let mut out = vec![0x00u8; 0x1000];

        println!("Allocated space for buffer.");

        let mut rng = StdRng::seed_from_u64(self.seed);

        println!("Seeded RNG.");

        let f = bin
            .functions
            .iter()
            .filter(|f| rvas.is_empty() || rvas.contains(&f.rva));

        let mut branches = f
            .map(|f| f.branches.iter().map(Arc::clone).collect::<Vec<_>>())
            .flatten()
            .collect::<Vec<_>>();

        println!("Found {} total branches.", branches.len());

        branches.shuffle(&mut rng);

        println!("Shuffled branches.");

        let mut branch_rva_to_ip = Vec::new();
        let mut all_branches_to_patch = Vec::new();
        let mut oep_branch_rva_to_ip = Vec::new();
        let mut oep_all_branches_to_patch = Vec::new();

        let oep_rva = bin
            .bin
            .pe
            .optional_header_64
            .unwrap()
            .address_of_entry_point as usize;

        let mut oep_ip = 0;
        let mut ip = 0;

        for b in &branches {
            let is_branch_in_oep = b.func_rva == oep_rva;

            if b.is_call_target {
                if is_branch_in_oep {
                    oep_ip = align_up(oep_ip, 16);
                } else {
                    ip = align_up(ip, 16);
                }
                // println!("{:#X?} {:#X?}", b.rva, ip);
            }

            if is_branch_in_oep {
                oep_branch_rva_to_ip.push((b.rva, oep_ip));
            } else {
                branch_rva_to_ip.push((b.rva, ip));
            }

            // if b.rva == 0x1f49 {
            //     println!("{:#X?}", branches);
            // }

            let (buffer, mut branches_to_patch) = b.relocate(
                &bin,
                if is_branch_in_oep { oep_ip } else { ip },
                self.seed,
                config,
            )?;

            if is_branch_in_oep {
                oep_all_branches_to_patch.append(&mut branches_to_patch);
            } else {
                all_branches_to_patch.append(&mut branches_to_patch);
            }

            // stop scattering branches if we ran out of room
            // or expand output buffer
            if is_branch_in_oep {
                if oep_ip + buffer.len() >= oep_out.len() {
                    oep_out.resize(oep_out.len() + 0x1000, 0);
                }
            } else {
                if ip + buffer.len() >= out.len() {
                    out.resize(out.len() + 0x1000, 0);
                }
            }

            if is_branch_in_oep {
                oep_out[oep_ip..(oep_ip + buffer.len())].copy_from_slice(&buffer);
                oep_ip += buffer.len();
            } else {
                out[ip..(ip + buffer.len())].copy_from_slice(&buffer);
                ip += buffer.len();
            }
        }

        // shrink output buffer to fit max ip
        out.resize(align_up(ip, 0x1000), 0);
        oep_out.resize(align_up(oep_ip, 0x1000), 0);

        oep_branch_rva_to_ip.sort_by_key(|x| x.0);
        branch_rva_to_ip.sort_by_key(|x| x.0);

        println!("Relocated branches.");

        let mem = out.as_mut_ptr() as usize;
        let oep_mem = oep_out.as_mut_ptr() as usize;

        let data_offset = align_up(out.len(), 0x1000);

        for a in &all_branches_to_patch {
            if a.is_data_ref {
                let (rva, size) = bin
                    .data_containing_rva(a.original_target_rva)
                    .unwrap_or_else(|| (a.original_target_rva, a.data_size));

                // println!("{:X} {:X}", a.original_target_rva, rva);

                // alloc area for this variable if doesnt exist yet
                data.entry(rva).or_insert_with(|| {
                    // println!("{:X} {:X}", a.original_target_rva, a.instr_rel32_offset);
                    // let (rva, size) = bin.data_containing_rva(a.original_target_rva).unwrap();
                    // .unwrap_or_else(|| (a.original_target_rva, a.data_size));

                    let ptr = data_offset + data_out.len();

                    println!(
                        "({:X}, {rva:X}, {size:X}) => {ptr:X}",
                        a.original_target_rva
                    );

                    let aligned_size = align_up(size, 0x8);
                    let mut buffer = vec![0u8; aligned_size];

                    if let Some(b) = bin.bin.read_bytes(rva)
                        && b.len() > 0
                    {
                        buffer[..size].copy_from_slice(&b[..size]);
                    }
                    data_out.append(&mut buffer);

                    ptr
                });
            }
        }
        for a in &oep_all_branches_to_patch {
            if a.is_data_ref {
                let (rva, size) = bin
                    .data_containing_rva(a.original_target_rva)
                    .unwrap_or_else(|| (a.original_target_rva, a.data_size));

                // println!("{:X} {:X}", a.original_target_rva, rva);

                // alloc area for this variable if doesnt exist yet
                data.entry(rva).or_insert_with(|| {
                    // println!("{:X} {:X}", a.original_target_rva, a.instr_rel32_offset);
                    // let (rva, size) = bin.data_containing_rva(a.original_target_rva).unwrap();
                    // .unwrap_or_else(|| (a.original_target_rva, a.data_size));

                    let ptr = data_offset + data_out.len();

                    println!(
                        "OEP ({:X}, {rva:X}, {size:X}) => {ptr:X}",
                        a.original_target_rva
                    );

                    let aligned_size = align_up(size, 0x8);
                    let mut buffer = vec![0u8; aligned_size];

                    if let Some(b) = bin.bin.read_bytes(rva)
                        && b.len() > 0
                    {
                        buffer[..size].copy_from_slice(&b[..size]);
                    }
                    data_out.append(&mut buffer);

                    ptr
                });
            }
        }

        // patch branches in parallel
        all_branches_to_patch.iter().for_each(|patchable_branch| {
            if patchable_branch.is_data_ref {
                let src = patchable_branch.next_ip;
                let (rva, size) = bin
                    .data_containing_rva(patchable_branch.original_target_rva)
                    .unwrap_or_else(|| {
                        (
                            patchable_branch.original_target_rva,
                            patchable_branch.data_size,
                        )
                    });
                let diff = patchable_branch.original_target_rva - rva;

                let mut dst = *data.get(&rva).unwrap() + diff;

                let mut rel32: i32 = dst.checked_signed_diff(src).unwrap().try_into().unwrap();

                // most likely safe because we will never repatch the same branch twice at the same time
                // (or at least then its highly unlikely and we would be creating other issues, for ex.)
                // a race condition where two similar branches meet, etc.
                unsafe {
                    (mem as *mut [u8; 4])
                        .byte_add(patchable_branch.instr_rel32_offset)
                        .write_unaligned(rel32.to_le_bytes());
                }

                return;
            }

            // println!(
            //     "{:X} {:X}",
            //     patchable_branch.original_target_rva, patchable_branch.next_ip
            // );

            let src = patchable_branch.next_ip;
            let index = match branch_rva_to_ip
                .binary_search_by(|(rva, ip)| rva.cmp(&patchable_branch.original_target_rva))
            {
                Ok(x) => x,
                Err(_) => return,
            };
            let dst = branch_rva_to_ip[index].1;
            let mut rel32: i32 = dst.checked_signed_diff(src).unwrap().try_into().unwrap();

            // most likely safe because we will never repatch the same branch twice at the same time
            // (or at least then its highly unlikely and we would be creating other issues, for ex.)
            // a race condition where two similar branches meet, etc.
            unsafe {
                (mem as *mut [u8; 4])
                    .byte_add(patchable_branch.instr_rel32_offset)
                    .write_unaligned(rel32.to_le_bytes());
            }

            // out[patchable_branch.instr_rel32_offset
            //     ..(patchable_branch.instr_rel32_offset + size_of::<i32>())]
            //     .copy_from_slice(&rel32.to_le_bytes());
        });
        oep_all_branches_to_patch
            .iter()
            .for_each(|patchable_branch| {
                if patchable_branch.is_data_ref {
                    let src = patchable_branch.next_ip;
                    let (rva, size) = bin
                        .data_containing_rva(patchable_branch.original_target_rva)
                        .unwrap_or_else(|| {
                            (
                                patchable_branch.original_target_rva,
                                patchable_branch.data_size,
                            )
                        });
                    let diff = patchable_branch.original_target_rva - rva;

                    let mut dst = *data.get(&rva).unwrap() + diff;

                    let mut rel32: i32 = dst.checked_signed_diff(src).unwrap().try_into().unwrap();

                    rel32 += oep_page_offset;

                    // most likely safe because we will never repatch the same branch twice at the same time
                    // (or at least then its highly unlikely and we would be creating other issues, for ex.)
                    // a race condition where two similar branches meet, etc.
                    unsafe {
                        (oep_mem as *mut [u8; 4])
                            .byte_add(patchable_branch.instr_rel32_offset)
                            .write_unaligned(rel32.to_le_bytes());
                    }

                    return;
                }

                // println!(
                //     "{:X} {:X}",
                //     patchable_branch.original_target_rva, patchable_branch.next_ip
                // );

                let src = patchable_branch.next_ip;
                let mut index_is_not_oep_table = false;
                let index = match oep_branch_rva_to_ip
                    .binary_search_by(|(rva, ip)| rva.cmp(&patchable_branch.original_target_rva))
                {
                    Ok(x) => x,
                    Err(x) => {
                        match branch_rva_to_ip.binary_search_by(|(rva, ip)| {
                            rva.cmp(&patchable_branch.original_target_rva)
                        }) {
                            Ok(x) => {
                                index_is_not_oep_table = true;
                                x
                            }
                            Err(_) => return,
                        }
                    }
                };
                let dst = if index_is_not_oep_table {
                    branch_rva_to_ip[index].1
                } else {
                    oep_branch_rva_to_ip[index].1
                };
                let mut rel32: i32 = dst.checked_signed_diff(src).unwrap().try_into().unwrap();

                if index_is_not_oep_table {
                    rel32 += oep_page_offset;
                }

                // most likely safe because we will never repatch the same branch twice at the same time
                // (or at least then its highly unlikely and we would be creating other issues, for ex.)
                // a race condition where two similar branches meet, etc.
                unsafe {
                    (oep_mem as *mut [u8; 4])
                        .byte_add(patchable_branch.instr_rel32_offset)
                        .write_unaligned(rel32.to_le_bytes());
                }

                // out[patchable_branch.instr_rel32_offset
                //     ..(patchable_branch.instr_rel32_offset + size_of::<i32>())]
                //     .copy_from_slice(&rel32.to_le_bytes());
            });

        println!("Patched branch offsets.");

        let dt = Instant::now().duration_since(start_time);

        println!("Done in {dt:?}.");

        let new_oep = oep_branch_rva_to_ip[oep_branch_rva_to_ip
            .binary_search_by(|(rva, ip)| rva.cmp(&oep_rva))
            .unwrap()]
        .1;

        Ok((out, data_out, (new_oep, oep_out), data_offset))
    }
}
