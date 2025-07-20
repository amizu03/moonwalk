use crate::{
    analyze::AnalyzedBin,
    bin::{Bin, RuntimeFunction},
    prelude::*,
};

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, ConditionCode, ConstantOffsets, Decoder,
    DecoderOptions, Instruction, InstructionBlock, Mnemonic, OpKind, Register, RflagsBits,
    code_asm::{
        CodeAssembler, get_gpr8, get_gpr16, get_gpr32, get_gpr64, ptr, qword_ptr, rax, rdx,
    },
};
use pe_parser::section::SectionFlags;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Display,
    sync::Arc,
};

pub fn align_up(value: usize, align: usize) -> usize {
    if !align.is_power_of_two() {
        panic!("Align value {align:X} is not power of two!")
    }

    (value + (align - 0x1)) & !(align - 0x1)
}

fn is_branch_or_jump(instr: &Instruction) -> bool {
    matches!(
        instr.mnemonic(),
        Mnemonic::Jmp
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jb
            | Mnemonic::Jae
            | Mnemonic::Jl
            | Mnemonic::Jge
            | Mnemonic::Jle
            | Mnemonic::Jg
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Jcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jrcxz
    )
}

fn is_unconditional_jump(instr: &Instruction) -> bool {
    instr.mnemonic() == Mnemonic::Jmp
}

fn is_ret(instr: &Instruction) -> bool {
    matches!(
        instr.mnemonic(),
        Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iretq | Mnemonic::Sysretq
    )
}

pub fn trace_function(code: &[u8], start_rip: usize) -> Vec<usize> {
    let mut visited: HashSet<usize> = HashSet::new();
    let mut to_visit: VecDeque<usize> = VecDeque::new();

    to_visit.push_back(start_rip);

    while let Some(rip) = to_visit.pop_front() {
        if visited.contains(&rip) {
            continue;
        }

        // let visit_count = visited.len();
        visited.insert(rip);

        // if start_rip == 0x1000 && visited.len() != visit_count {
        //     println!("BR{}:", visit_count);
        // }

        let offset = (rip - start_rip) as usize;

        if offset >= code.len() {
            continue;
        }

        let mut decoder = Decoder::with_ip(64, &code[offset..], rip as u64, DecoderOptions::NONE);

        while decoder.can_decode() {
            let instr = decoder.decode();
            let addr = instr.ip();

            // if start_rip == 0x1000 {
            //     println!("{:016X}: {}", addr, instr);
            // }

            if is_ret(&instr) {
                break;
            }

            if is_branch_or_jump(&instr) {
                if instr.op0_kind() == OpKind::NearBranch64 {
                    let target = instr.near_branch_target();
                    to_visit.push_back(target as usize);
                }

                if !is_unconditional_jump(&instr) {
                    // Fall-through address
                    to_visit.push_back(instr.next_ip() as usize);
                }

                break;
            }

            if instr.mnemonic() == Mnemonic::Call {
                // Skip calls entirely — do not enqueue
            }
        }
    }

    let mut visited = visited.iter().cloned().collect::<Vec<_>>();

    visited.sort();

    // make sure we dont go past end of code
    if let Some(last) = visited.last() {
        if *last > start_rip + code.len() {
            visited.pop();
        }
    }

    visited
}

fn jcc_to_rel32(code: Code) -> Option<Code> {
    Some(match code.condition_code() {
        ConditionCode::None => Code::Jmp_rel32_64,
        ConditionCode::o => Code::Jo_rel32_64,
        ConditionCode::no => Code::Jno_rel32_64,
        ConditionCode::b => Code::Jb_rel32_64,
        ConditionCode::ae => Code::Jae_rel32_64,
        ConditionCode::e => Code::Je_rel32_64,
        ConditionCode::ne => Code::Jne_rel32_64,
        ConditionCode::be => Code::Jbe_rel32_64,
        ConditionCode::a => Code::Ja_rel32_64,
        ConditionCode::s => Code::Js_rel32_64,
        ConditionCode::ns => Code::Jns_rel32_64,
        ConditionCode::p => Code::Jp_rel32_64,
        ConditionCode::np => Code::Jnp_rel32_64,
        ConditionCode::l => Code::Jl_rel32_64,
        ConditionCode::ge => Code::Jge_rel32_64,
        ConditionCode::le => Code::Jle_rel32_64,
        ConditionCode::g => Code::Jg_rel32_64,
    })
}

fn create_branch(code: Code, target: usize) -> Instruction {
    let mut instr = Instruction::default();
    instr.set_code(code);
    // instr.set_near_branch32(target as _);
    instr.set_near_branch64(target as _);
    instr
}

pub fn decode_single_instruction(bytes: &[u8], ip: usize) -> Option<Instruction> {
    let mut decoder = Decoder::with_ip(64, bytes, ip as _, DecoderOptions::NONE);
    let instr = decoder.decode();

    if instr.is_invalid() {
        None
    } else {
        Some(instr)
    }
}

// fn rewrite_rip_relative(instr: &Instruction, new_ip: u64) -> Option<Instruction> {
//     // Check for RIP-relative memory operand
//     if instr.memory_base() == Register::RIP {
//         let mut new_instr = Instruction::default();
//         new_instr.set_code(instr.code());

//         // Copy operands, replacing RIP-relative memory address with target addr
//         let displacement = instr.memory_displacement64();
//         let target = instr.ip() + instr.len() as u64 + displacement;

//         // Recompute new displacement from new_ip
//         let new_disp = target.wrapping_sub(new_ip + instr.len() as u64);

//         new_instr.set_memory_displacement64(new_disp);
//         new_instr.set_memory_base(Register::RIP);
//         new_instr.set_memory_index(Register::None);
//         new_instr.set_memory_index_scale(1);
//         // new_instr.set_memory_displ_size(new_value);
//         new_instr.set_memory_size(instr.memory_size());

//         for i in 0..instr.op_count() {
//             match instr.op_kind(i) {
//                 OpKind::Memory => {
//                     new_instr.set_op0_kind(OpKind::Memory);
//                 }
//                 OpKind::Register => {
//                     new_instr.set_op_register(i, instr.op_register(i));
//                 }
//                 OpKind::Immediate8
//                 | OpKind::Immediate16
//                 | OpKind::Immediate32
//                 | OpKind::Immediate64 => {
//                     new_instr.set_immediate(i, instr.immediate(i));
//                 }
//                 _ => {} // Handle others as needed
//             }
//         }

//         Some(new_instr)
//     } else {
//         None
//     }
// }

#[derive(Debug, Clone, Copy)]
pub struct PatchableBranch {
    pub original_target_rva: usize,
    pub instr_rel32_offset: usize,
    pub next_ip: usize,
}

#[derive(Debug, Clone)]
pub struct BranchBlock {
    pub is_call_target: bool,
    pub rva: usize,
    pub next_rva: usize,
    pub instructions: Vec<Instruction>,
}

fn obf_mov(rng: &mut StdRng, a: &mut CodeAssembler, inst: &mut Instruction) -> bool {
    let mut was_obfuscated = false;

    let op_kind0 = inst.op_kind(0);

    if op_kind0 == OpKind::Register {
        let op_kind1 = inst.op_kind(1);
        let reg = inst.op0_register();

        if reg.is_gpr() {
            was_obfuscated = true;

            let rounds = rng.random_range(1..4);
            let mut vals: Vec<[usize; 5]> = Vec::new();

            for _ in 0..rounds {
                match op_kind1 {
                    OpKind::Immediate8 => {
                        let x = [
                            rng.random_range(1..=u8::MAX as usize),
                            rng.random_range(1..=u8::MAX as usize),
                            rng.random_range(1..=64),
                            rng.random_range(0..=2),
                            rng.random_range(0..=2),
                        ];

                        let mut v = inst.immediate8();
                        if x[3] == 0 {
                            v = v.rotate_left(x[2] as u32);
                        } else if x[3] == 1 {
                            v = v.rotate_right(x[2] as u32);
                        }
                        v ^= x[1] as u8;
                        if x[4] == 0 {
                            v = v.wrapping_sub(x[0] as u8);
                        } else if x[4] == 1 {
                            v = v.wrapping_add(x[0] as u8);
                        }

                        inst.set_immediate8(v);

                        vals.push(x);
                    }
                    OpKind::Immediate16 => {
                        let x = [
                            rng.random_range(i16::MAX as usize / 2..=i16::MAX as usize),
                            rng.random_range(i16::MAX as usize / 2..=i16::MAX as usize),
                            rng.random_range(1..=64),
                            rng.random_range(0..=2),
                            rng.random_range(0..=2),
                        ];

                        let mut v = inst.immediate16();
                        if x[3] == 0 {
                            v = v.rotate_left(x[2] as u32);
                        } else if x[3] == 1 {
                            v = v.rotate_right(x[2] as u32);
                        }
                        v ^= x[1] as u16;
                        if x[4] == 0 {
                            v = v.wrapping_sub(x[0] as u16);
                        } else if x[4] == 1 {
                            v = v.wrapping_add(x[0] as u16);
                        }

                        inst.set_immediate16(v);

                        vals.push(x);
                    }
                    OpKind::Immediate32 => {
                        let x = [
                            rng.random_range(u32::MAX as usize / 2..=u32::MAX as usize),
                            rng.random_range(u32::MAX as usize / 2..=u32::MAX as usize),
                            rng.random_range(1..=64),
                            rng.random_range(0..=2),
                            rng.random_range(0..=2),
                        ];

                        let mut v = inst.immediate32();
                        if x[3] == 0 {
                            v = v.rotate_left(x[2] as u32);
                        } else if x[3] == 1 {
                            v = v.rotate_right(x[2] as u32);
                        }
                        v ^= x[1] as u32;
                        if x[4] == 0 {
                            v = v.wrapping_sub(x[0] as u32);
                        } else if x[4] == 1 {
                            v = v.wrapping_add(x[0] as u32);
                        }

                        inst.set_immediate32(v);

                        vals.push(x);
                    }
                    OpKind::Immediate64 => {
                        let x = [
                            rng.random_range(i32::MAX as usize / 2..=i32::MAX as usize),
                            rng.random_range(i32::MAX as usize / 2..=i32::MAX as usize),
                            rng.random_range(1..=64),
                            rng.random_range(0..=2),
                            rng.random_range(0..=2),
                        ];

                        let mut v = inst.immediate64();
                        if x[3] == 0 {
                            v = v.rotate_left(x[2] as u32);
                        } else if x[3] == 1 {
                            v = v.rotate_right(x[2] as u32);
                        }
                        v ^= x[1] as u64;
                        if x[4] == 0 {
                            v = v.wrapping_sub(x[0] as u64);
                        } else if x[4] == 1 {
                            v = v.wrapping_add(x[0] as u64);
                        }

                        inst.set_immediate64(v);

                        vals.push(x);
                    }
                    _ => {
                        was_obfuscated = false;
                        break;

                        // [0, 0, 0]
                    }
                };
            }

            if was_obfuscated {
                use iced_x86::code_asm::*;

                a.add_instruction(*inst).unwrap();

                a.pushf().unwrap();

                for [add_val, xor_val, rot_val, is_sub, is_rotl] in vals {
                    if let Some(r) = get_gpr8(reg) {
                        a.not(r).unwrap();
                        if is_sub == 1 {
                            a.sub(r, add_val as u32).unwrap();
                        } else if is_sub == 0 {
                            a.add(r, add_val as u32).unwrap();
                        }
                        a.xor(r, xor_val as u32).unwrap();
                        if is_rotl == 1 {
                            a.rol(r, rot_val as u32).unwrap();
                        } else if is_rotl == 0 {
                            a.ror(r, rot_val as u32).unwrap();
                        }
                    } else if let Some(r) = get_gpr16(reg) {
                        a.not(r).unwrap();
                        if is_sub == 1 {
                            a.sub(r, add_val as u32).unwrap();
                        } else if is_sub == 0 {
                            a.add(r, add_val as u32).unwrap();
                        }
                        a.xor(r, xor_val as u32).unwrap();
                        if is_rotl == 1 {
                            a.rol(r, rot_val as u32).unwrap();
                        } else if is_rotl == 0 {
                            a.ror(r, rot_val as u32).unwrap();
                        }
                    } else if let Some(r) = get_gpr32(reg) {
                        a.not(r).unwrap();
                        if is_sub == 1 {
                            a.sub(r, add_val as u32).unwrap();
                        } else if is_sub == 0 {
                            a.add(r, add_val as u32).unwrap();
                        }
                        a.xor(r, xor_val as u32).unwrap();
                        if is_rotl == 1 {
                            a.rol(r, rot_val as u32).unwrap();
                        } else if is_rotl == 0 {
                            a.ror(r, rot_val as u32).unwrap();
                        }
                    } else if let Some(r) = get_gpr64(reg) {
                        a.not(r).unwrap();
                        if is_sub == 1 {
                            a.sub(r, add_val as i32).unwrap();
                        } else if is_sub == 0 {
                            a.add(r, add_val as i32).unwrap();
                        }
                        a.xor(r, xor_val as i32).unwrap();
                        if is_rotl == 1 {
                            a.rol(r, rot_val as u32).unwrap();
                        } else if is_rotl == 0 {
                            a.ror(r, rot_val as u32).unwrap();
                        }
                    }
                }

                a.popf().unwrap();
            }
        }
    }

    was_obfuscated
}

impl BranchBlock {
    pub fn relocate(
        &self,
        analyzed_bin: &AnalyzedBin,
        new_rva: usize,
        seed: u64,
    ) -> Result<(Vec<u8>, Vec<PatchableBranch>)> {
        let mut a = CodeAssembler::new(64).unwrap();

        let mut rng = StdRng::seed_from_u64(seed + self.rva as u64);
        let mut custom_instr = self.instructions.clone();

        for inst in &mut custom_instr {
            let mut was_obfuscated = false;

            if inst.is_ip_rel_memory_operand() {
                let data_rva = inst.memory_displacement64();

                let scn = analyzed_bin.bin.rva_to_file_offset(data_rva as usize).1;
                let cs = scn.get_characteristics().unwrap();

                let is_data_section = cs.contains(SectionFlags::IMAGE_SCN_CNT_INITALIZED_DATA)
                    || cs.contains(SectionFlags::IMAGE_SCN_CNT_UNINITALIZED_DATA);
                let is_code_section = cs.contains(SectionFlags::IMAGE_SCN_CNT_CODE);

                if is_data_section && !is_code_section {
                    // println!("{data_rva:X}");
                    // let new_rva = analyzed_bin.data_containing_rva(data_rva as usize).unwrap();

                    // inst.set_memory_displacement64(new_rva as u64);
                    // println!("MEM: {data_rva:X} => {new_rva:X}");
                }
            }

            if is_branch_or_jump(inst) && !inst.is_ip_rel_memory_operand() {
                let branch_target = inst.near_branch_target();

                if branch_target != 0 {
                    // force branch to use rel32 offset for easy patching
                    inst.set_code(jcc_to_rel32(inst.code()).unwrap());
                    // inst.set_memory_displ_size(new_value);

                    // println!("BR: {inst}; 0x{branch_target:X}");
                }
                // else {
                //     println!("YAY!");
                // }
            }

            let mnemonic = inst.mnemonic();

            if mnemonic == Mnemonic::Call {
                let branch_target = inst.near_branch_target();

                if branch_target != 0 {
                    // println!("CALL! {branch_target:X}");
                }
            }
            else if mnemonic == Mnemonic::Shl {
                let op_kind0 = inst.op_kind(0);
                let op_kind1 = inst.op_kind(1);

                if op_kind0 == OpKind::Register && op_kind1 == OpKind::Immediate8 {
                    let reg = inst.op0_register();

                    if let Some(r) = get_gpr64(reg) {
                        was_obfuscated = true;

                        a.pushf().unwrap();
                        a.push(rax).unwrap();
                        a.push(rdx).unwrap();
                        if rng.random_range(0..=1) == 0 {
                            a.xchg(r, rax).unwrap();
                        } else {
                            a.xchg(rax, r).unwrap();
                        }
                        let mut tmp_a = CodeAssembler::new(64).unwrap();
                        tmp_a.mov(r, 2u64.pow(inst.immediate8() as u32)).unwrap();
                        let mut tmp_a = tmp_a.take_instructions();
                        obf_mov(&mut rng, &mut a, &mut tmp_a[0]);
                        a.div(r).unwrap();
                        if rng.random_range(0..=1) == 0 {
                            a.xchg(r, rax).unwrap();
                        } else {
                            a.xchg(rax, r).unwrap();
                        }
                        a.pop(rdx).unwrap();
                        a.pop(rax).unwrap();
                        a.popf().unwrap();
                    }
                }
            } else if mnemonic == Mnemonic::Shr {
                let op_kind0 = inst.op_kind(0);
                let op_kind1 = inst.op_kind(1);

                if op_kind0 == OpKind::Register && op_kind1 == OpKind::Immediate8 {
                    let reg = inst.op0_register();

                    if let Some(r) = get_gpr64(reg) {
                        was_obfuscated = true;

                        a.pushf().unwrap();
                        a.push(rax).unwrap();
                        a.push(rdx).unwrap();
                        if rng.random_range(0..=1) == 0 {
                            a.xchg(r, rax).unwrap();
                        } else {
                            a.xchg(rax, r).unwrap();
                        }
                        let mut tmp_a = CodeAssembler::new(64).unwrap();
                        tmp_a.mov(r, 2u64.pow(inst.immediate8() as u32)).unwrap();
                        let mut tmp_a = tmp_a.take_instructions();
                        obf_mov(&mut rng, &mut a, &mut tmp_a[0]);
                        a.mul(r).unwrap();
                        if rng.random_range(0..=1) == 0 {
                            a.xchg(r, rax).unwrap();
                        } else {
                            a.xchg(rax, r).unwrap();
                        }
                        a.pop(rdx).unwrap();
                        a.pop(rax).unwrap();
                        a.popf().unwrap();
                    }
                }
            } else if mnemonic == Mnemonic::Xor {
                let op_kind0 = inst.op_kind(0);
                let op_kind1 = inst.op_kind(1);

                if op_kind0 == OpKind::Register && op_kind1 == OpKind::Register {
                    let op_reg0 = inst.op_register(0);
                    let op_reg1 = inst.op_register(1);

                    if op_reg0.is_gpr() && op_reg0 == op_reg1 {
                        was_obfuscated = true;

                        if let Some(r) = get_gpr8(op_reg0) {
                            a.mov(r, 0).unwrap();
                        } else if let Some(r) = get_gpr16(op_reg0) {
                            a.mov(r, 0).unwrap();
                        } else if let Some(r) = get_gpr32(op_reg0) {
                            a.mov(r, 0).unwrap();
                        } else if let Some(r) = get_gpr64(op_reg0) {
                            a.mov(r, 0u64).unwrap();
                        }
                    }
                }
            } else if mnemonic == Mnemonic::Mov {
                was_obfuscated = obf_mov(&mut rng, &mut a, inst);

                if !was_obfuscated {
                    let op0 = inst.op_kind(0);
                    let op1 = inst.op_kind(1);

                    if inst.is_ip_rel_memory_operand() {
                        was_obfuscated = true;

                        let disp = inst.memory_displacement64();
                        let reg = inst.op_register(0);

                        if let Some(r) = get_gpr64(reg) {
                            let mut tmp_a = CodeAssembler::new(64).unwrap();
                            tmp_a.mov(r, disp).unwrap();
                            let mut tmp_a = tmp_a.take_instructions();
                            obf_mov(&mut rng, &mut a, &mut tmp_a[0]);

                            a.mov(r, qword_ptr(r)).unwrap();
                        } else if let Some(r) = get_gpr32(reg) {
                        } else if let Some(r) = get_gpr16(reg) {
                        } else if let Some(r) = get_gpr8(reg) {
                        }
                    }
                }
            }

            if !was_obfuscated {
                a.add_instruction(*inst).unwrap();
            }
        }

        // let assembled = a.assemble(self.rva as u64).unwrap();
        // let mut decoded = Decoder::with_ip(64, &assembled, self.rva as u64, DecoderOptions::NONE);
        let mut custom_instr = a.take_instructions();
        // while decoded.can_decode() {
        //     let i = decoded.decode();
        //     println!("{i}");
        //     custom_instr.push(i);
        // }

        let last_inst = custom_instr.last().unwrap();

        // we already separated everything into branches, so we only need to create a fake unconditional branch
        // after the conditional branch to redirect to the new branch
        let is_fallthrough_branch = if is_branch_or_jump(last_inst) {
            !is_unconditional_jump(last_inst)
        } else {
            !is_ret(last_inst)
        };

        // println!("{is_fallthrough_branch}");

        let mut block = InstructionBlock::new(&custom_instr, new_rva as _);
        let mut encode = BlockEncoder::encode(
            64,
            block,
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
                | BlockEncoderOptions::RETURN_CONSTANT_OFFSETS
                | BlockEncoderOptions::DONT_FIX_BRANCHES,
        );
        let mut buffer = encode.map_err(|_| Error::RelocateBranch {
            from_rva: self.rva,
            to_rva: new_rva,
        })?;

        if buffer.new_instruction_offsets.len() != buffer.constant_offsets.len() {
            panic!("WRONG LEN!");
        }

        let mut branches_to_patch = Vec::new();

        for new_inst_offset in &buffer.new_instruction_offsets {
            let ip = new_rva + *new_inst_offset as usize;
            let inst =
                decode_single_instruction(&buffer.code_buffer[*new_inst_offset as usize..], ip)
                    .unwrap();

            if is_branch_or_jump(&inst) && !inst.is_ip_rel_memory_operand() {
                let branch_target = inst.near_branch_target();

                if branch_target != 0 && branch_target as usize != new_rva {
                    let next_ip = inst.next_ip();

                    branches_to_patch.push(PatchableBranch {
                        original_target_rva: branch_target as usize,
                        instr_rel32_offset: ip + inst.len() - size_of::<i32>(),
                        next_ip: next_ip as usize,
                    });
                }
            } else if inst.mnemonic() == Mnemonic::Call {
                let branch_target = inst.near_branch_target();

                if branch_target != 0 && branch_target as usize != new_rva {
                    let next_ip = inst.next_ip();

                    branches_to_patch.push(PatchableBranch {
                        original_target_rva: branch_target as usize,
                        instr_rel32_offset: ip + inst.len() - size_of::<i32>(),
                        next_ip: next_ip as usize,
                    });
                }
            } else if inst.is_ip_rel_memory_operand() {
                let ip_rel_rva = inst.ip_rel_memory_address();

                if ip_rel_rva != 0 {
                    let scn = analyzed_bin.bin.rva_to_file_offset(ip_rel_rva as usize).1;
                    let cs = scn.get_characteristics().unwrap();

                    let is_data_section = cs.contains(SectionFlags::IMAGE_SCN_CNT_INITALIZED_DATA)
                        || cs.contains(SectionFlags::IMAGE_SCN_CNT_UNINITALIZED_DATA);
                    let is_code_section = cs.contains(SectionFlags::IMAGE_SCN_CNT_CODE);

                    if is_code_section && !is_data_section {
                        let next_ip = inst.next_ip();

                        branches_to_patch.push(PatchableBranch {
                            original_target_rva: ip_rel_rva as usize,
                            instr_rel32_offset: ip + inst.len() - size_of::<i32>(),
                            next_ip: next_ip as usize,
                        });
                    }
                }
            }
        }

        let mut buffer = buffer.code_buffer;

        // add extra rel32 jump after this block/branch so we can modify the next destination after we figure
        // out where to place all the blocks
        if is_fallthrough_branch {
            buffer.append(&mut vec![0xE9, 0x00, 0x00, 0x00, 0x00]);

            // println!("FTB: {:X}", self.next_rva);

            branches_to_patch.push(PatchableBranch {
                original_target_rva: self.next_rva,
                instr_rel32_offset: new_rva + buffer.len() - size_of::<i32>(),
                next_ip: new_rva + buffer.len(),
            });
        }

        Ok((buffer, branches_to_patch))
    }
}

#[derive(Debug, Clone)]
pub struct AnalyzedFunction {
    pub name: String,
    pub rva: usize,
    pub branches: Vec<Arc<BranchBlock>>,
    pub data_refs: Vec<(usize, usize)>,
}

impl Display for AnalyzedFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{} proc near\n", self.name))?;

        for (br_i, branch) in self.branches.iter().enumerate() {
            if !branch.is_call_target {
                f.write_str(&format!("BR{br_i}:\n"))?;
            }

            for inst in &branch.instructions {
                f.write_str(&format!("    {inst}"))?;

                let br_target = inst.near_branch_target();

                // branch target in current block
                if br_target != 0 {
                    if let Some((i_br_target, br_target)) = self
                        .branches
                        .iter()
                        .enumerate()
                        .find(|(i, b)| b.rva == br_target as usize)
                    {
                        f.write_str(&format!("; BR{i_br_target}"))?;
                        // br_target.rva
                    }
                }

                f.write_str("\n");
            }
        }

        f.write_str(&format!("{} endp\n", self.name))?;

        f.write_str("\n")
    }
}

pub fn fmt_flags(rf: u32) -> String {
    fn append(sb: &mut String, s: &str) {
        if !sb.is_empty() {
            sb.push_str(", ");
        }
        sb.push_str(s);
    }

    let mut sb = String::new();
    if (rf & RflagsBits::OF) != 0 {
        append(&mut sb, "OF");
    }
    if (rf & RflagsBits::SF) != 0 {
        append(&mut sb, "SF");
    }
    if (rf & RflagsBits::ZF) != 0 {
        append(&mut sb, "ZF");
    }
    if (rf & RflagsBits::AF) != 0 {
        append(&mut sb, "AF");
    }
    if (rf & RflagsBits::CF) != 0 {
        append(&mut sb, "CF");
    }
    if (rf & RflagsBits::PF) != 0 {
        append(&mut sb, "PF");
    }
    if (rf & RflagsBits::DF) != 0 {
        append(&mut sb, "DF");
    }
    if (rf & RflagsBits::IF) != 0 {
        append(&mut sb, "IF");
    }
    if (rf & RflagsBits::AC) != 0 {
        append(&mut sb, "AC");
    }
    if (rf & RflagsBits::UIF) != 0 {
        append(&mut sb, "UIF");
    }
    if sb.is_empty() {
        sb.push_str("<empty>");
    }
    sb
}

impl AnalyzedFunction {
    pub fn from_runtime_function(bin: &Bin, rt: &RuntimeFunction) -> Result<Self> {
        let mut data_refs = Vec::new();
        let mut code_refs = Vec::new();

        // slice function raw bytes
        let func_view = bin.read_bytes(rt.fn_start as usize);
        let func_raw = &func_view[..(rt.fn_end - rt.fn_start) as usize];

        // trace function branches (excluding calls)
        let branches = trace_function(func_raw, rt.fn_start as _);
        let mut separated_branches = Vec::new();

        // separate branches in memory order and mark the branch entry/rva
        for (i_branch, branch) in branches.iter().enumerate() {
            let mut ip = 0;
            let mut decoder = Decoder::with_ip(
                64,
                &func_raw[*branch - rt.fn_start as usize..],
                *branch as _,
                DecoderOptions::NONE,
            );

            let mut instructions = Vec::new();
            let mut branch_rva = 0;

            while decoder.can_decode() {
                let instr = decoder.decode();

                ip = instr.ip() as usize;

                if match branches.get(i_branch + 1) {
                    Some(next_br) => ip >= *next_br,
                    None => ip >= rt.fn_end as usize,
                } {
                    break;
                }

                if branch_rva == 0 {
                    branch_rva = ip;
                }

                if instr.is_ip_rel_memory_operand() {
                    let mem_size = instr.memory_size();
                    let rva = instr.ip_rel_memory_address();

                    let containing_section = bin.rva_to_file_offset(rva as usize).1;

                    if let Some(cs) = containing_section.get_characteristics() {
                        // RVA is inside data section
                        if cs.contains(SectionFlags::IMAGE_SCN_CNT_UNINITALIZED_DATA)
                            || cs.contains(SectionFlags::IMAGE_SCN_CNT_INITALIZED_DATA)
                        {
                            data_refs.push((rva as usize, mem_size.size()));
                        }
                        // RVA is inside code section
                        else if cs.contains(SectionFlags::IMAGE_SCN_CNT_CODE) {
                            code_refs.push(rva as usize);
                        }
                    } else {
                        panic!("rip-relative memory ref not in a section!");
                    }
                }

                instructions.push(instr);
            }

            if !instructions.is_empty() {
                separated_branches.push(Arc::new(BranchBlock {
                    is_call_target: separated_branches.is_empty(),
                    rva: branch_rva,
                    next_rva: ip,
                    instructions,
                }));
            }
        }

        let name = bin
            .symbols
            .code
            .get(&(rt.fn_start as usize))
            .map(|x| x.to_string())
            .unwrap_or_else(|| format!("sub_{:X}", rt.fn_start as usize));

        let x = Self {
            name,
            rva: rt.fn_start as usize,
            branches: separated_branches,
            data_refs,
        };

        Ok(x)
    }
}
