use std::time::Instant;

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

impl Obfuscator {
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    pub fn scatter(&self, bin: &AnalyzedBin, rvas: &[usize]) -> Result<Box<[u8]>> {
        let mut start_time = Instant::now();

        let mut out = vec![0xCCu8; 0x1000];

        println!("Allocated space for buffer.");

        let mut rng = StdRng::seed_from_u64(self.seed);

        println!("Seeded RNG.");

        let f = bin
            .functions
            .iter()
            .filter(|f| rvas.is_empty() || rvas.contains(&f.rva))
            .into_iter();

        let mut branches = f
            .map(|f| f.branches.iter().map(Arc::clone).collect::<Vec<_>>())
            .flatten()
            .collect::<Vec<_>>();

        println!("Found {} total branches.", branches.len());

        branches.shuffle(&mut rng);

        println!("Shuffled branches.");

        let mut branch_rva_to_ip = Vec::new();
        let mut all_branches_to_patch = Vec::new();

        let mut ip = 0;
        for b in &branches {
            if b.is_call_target {
                ip = align_up(ip, 16);
            }

            branch_rva_to_ip.push((b.rva, ip));

            let (buffer, mut branches_to_patch) = b.relocate(&bin, ip, self.seed)?;

            all_branches_to_patch.append(&mut branches_to_patch);

            // stop scattering branches if we ran out of room
            // or expand output buffer
            if ip + buffer.len() >= out.len() {
                out.resize(out.len() + 0x1000, 0);
                // return Err(Error::OutputBufferTooSmall);
            }

            out[ip..(ip + buffer.len())].copy_from_slice(&buffer);

            ip += buffer.len();
        }

        // shrink output buffer to fit max ip
        out.resize(align_up(ip, 0x1000), 0);

        branch_rva_to_ip.sort_by_key(|x| x.0);

        println!("Relocated branches.");

        let mem = out.as_mut_ptr() as usize;

        // patch branches in parallel
        all_branches_to_patch.iter().for_each(|patchable_branch| {
            let src = patchable_branch.next_ip;
            let dst = branch_rva_to_ip[branch_rva_to_ip
                .binary_search_by(|(rva, ip)| rva.cmp(&patchable_branch.original_target_rva))
                .unwrap()]
            .1;
            let rel32: i32 = dst.checked_signed_diff(src).unwrap().try_into().unwrap();

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

        println!("Patched branch offsets.");

        let out = out.into_boxed_slice();
        let dt = Instant::now().duration_since(start_time);

        println!("Done in {dt:?}.");

        Ok(out)
    }
}
