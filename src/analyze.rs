use super::bin::Bin;
use crate::{function::AnalyzedFunction, prelude::*};

use std::{collections::HashMap, sync::Arc};

pub struct AnalyzedBin {
    pub bin: Arc<Bin>,
    pub functions: Vec<AnalyzedFunction>,
    // RVA => SIZE_BYTES
    pub data: Vec<(usize, usize)>,
}

impl AnalyzedBin {
    pub fn data_containing_rva(&self, target_rva: usize) -> Option<(usize, usize)> {
        for (rva, size) in &self.data {
            if (*rva..(*rva + size)).contains(&target_rva) {
                let offset_from_rva = target_rva - rva;

                // println!("{offset_from_rva:X} {:X}", *size);

                return Some((*rva, *size));
            }
        }

        None
    }

    // analyzes code refs, data refs, and functions/branches in parallel
    pub fn analyze_bin(bin: Arc<Bin>) -> Self {
        let functions = bin
            .rtt
            .iter()
            .map(|(f, s)| AnalyzedFunction::from_runtime_function(&bin, f).unwrap())
            .collect::<Vec<_>>();

        // collect all data refs
        let mut data_refs: Vec<(usize, usize)> = functions
            .iter()
            .map(|f| f.data_refs.clone())
            .flatten()
            .collect();

        for (rva, data) in &bin.symbols.data {
            // add data from symbol if it wasnt found
            match data_refs.iter().find(|x| x.0 == *rva) {
                Some(_) => {
                    // println!("DATA: {data} {rva:X}");
                }
                None => {
                    // println!("DATA: {data}");
                    data_refs.push((*rva, 1));
                }
            }
        }

        // sort by data RVA
        data_refs.sort_by_key(|d| d.0);

        let mut data = Vec::new();

        let mut collect_rva = 0;
        let mut max_data_size = 0;

        // merge data refs into largest blocks
        let mut i = 0;
        while i < data_refs.len() {
            let (rva, size) = data_refs[i];

            if collect_rva == 0 {
                collect_rva = rva;
                max_data_size = size;
            }

            let mut found_next = false;

            for j in (i..data_refs.len()).skip(1) {
                let (next_rva, next_size) = data_refs[j];

                if next_rva > rva {
                    let max_size = next_rva - collect_rva;

                    // if data_refs
                    //     .iter()
                    //     .find(|(rva, size)| {
                    //         (*rva..=(*rva + *size)).contains(&collect_rva)
                    //             && (*rva..=(*rva + *size)).contains(&(collect_rva + max_size))
                    //     })
                    //     .is_none()
                    // {
                    // println!("{collect_rva:X} {max_size:X}");
                    data.push((collect_rva, max_size));
                    // }

                    i = j;
                    found_next = true;

                    collect_rva = 0;
                    max_data_size = 0;

                    break;
                } else {
                    max_data_size = max_data_size.max(next_size);
                }
            }

            if !found_next && collect_rva != 0 {
                // println!("{collect_rva:X} {max_data_size:X}");
                data.push((collect_rva, max_data_size));
                collect_rva = 0;
                max_data_size = 0;
            }

            i += 1;
        }

        // fix incorrect data sizes
        // TODO: use PDB to increase accuracy
        for d in &mut data {
            if d.1 > 64 && d.1 < 0x1000 {
                d.1 = 64;
                println!("Fixed data size");
            }

            if d.1 == 0 && d.1 < 0x1000 {
                d.1 = 64;
                println!("Fixed data size");
            }
        }

        for i in 0..data.len() {
            let (collect_rva, max_size) = data[i];

            if let Some((next_rva, next_size)) = data.get(i + 1) {
                if collect_rva + max_size < *next_rva {
                    if let Some(ret) = data_refs
                        .iter()
                        .find(|(rva, size)| (*rva..(*rva + *size)).contains(&collect_rva))
                    {
                        data[i].1 = ret.1;
                    }
                }
            }
        }

        data.dedup_by_key(|x| x.0);

        Self {
            bin,
            functions,
            data,
        }
    }
}
