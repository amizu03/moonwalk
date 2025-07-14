// use memflow::prelude::v1::*;

// let inventory = Inventory::scan();
// let conn = inventory.builder().connector("qemu");
// let mut os = conn
//     .os("win32")
//     .build()
//     .expect("Failed to build OS connector");

// // parse_portable_executable(binary)

// let nt = os.module_by_name("ntoskrnl.exe").unwrap();
// let ke_query_auxiliary_counter_frequency = os
//     .module_export_by_name(&nt, "KeQueryAuxiliaryCounterFrequency")
//     .unwrap();

// let mov_rax_ptr =
//     (nt.base + ke_query_auxiliary_counter_frequency.offset).to_umem() as usize + 0x4;

// let ex_allocate_pool_2 = nt.base.to_umem() as usize
//     + os.module_export_by_name(&nt, "ExAllocatePool2")
//         .unwrap()
//         .offset as usize;

// let mut mem = os.cast_impl_memoryview().unwrap();

// let hal_fn_ptr = (mov_rax_ptr + 0x7).wrapping_add_signed(i32::from_ne_bytes(
//     mem.read::<[u8; 4]>((mov_rax_ptr + 0x3).into()).unwrap(),
// ) as isize);

// let mut nt_hdr = vec![0u8; 0x1000];
// mem.read_raw_into(nt.base, &mut nt_hdr[..]).unwrap();

// let pe = parse_portable_executable(&nt_hdr).unwrap();

// let pad2 = pe
//     .section_table
//     .iter()
//     .find(|s| s.name.starts_with(b"Pad2"))
//     .unwrap();
// let pad3 = pe
//     .section_table
//     .iter()
//     .find(|s| s.name.starts_with(b"Pad3"))
//     .unwrap();

// // push rcx
// // push rdx
// // push r8
// // push r9
// // sub rsp, 0x28
// // lea rax, [rip+0x0]
// // cmp byte ptr[rax+0x30], 1
// // jge done
// // inc byte ptr[rax+0x30]
// // mov rcx, [rax+0x0]
// // mov rdx, [rax+0x8]
// // mov r8, [rax+0x10]
// // mov r9, [rax+0x18]
// // call [rax+0x20]
// // mov [rip+0x28], rax
// // done:
// // xor rax, rax
// // add rsp, 0x28
// // pop r9
// // pop r8
// // pop rdx
// // pop rcx
// // ret
// let mut stub = [
//     0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x05, 0x00, 0x00,
//     0x00, 0x00, 0x80, 0x78, 0x30, 0x01, 0x7D, 0x1C, 0xFE, 0x40, 0x30, 0x48, 0x8B, 0x08, 0x48,
//     0x8B, 0x50, 0x08, 0x4C, 0x8B, 0x40, 0x10, 0x4C, 0x8B, 0x48, 0x18, 0xFF, 0x50, 0x20, 0x48,
//     0x89, 0x05, 0x28, 0x00, 0x00, 0x00, 0x48, 0x31, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0x41, 0x59,
//     0x41, 0x58, 0x5A, 0x59, 0xC3,
// ];

// #[repr(C)]
// #[derive(Debug, Default, Copy, Clone)]
// pub struct CallArgs {
//     pub args: [usize; 4],
//     pub target: usize,
//     pub retval: usize,
//     pub done: bool,
// }

// let mut pad2_raw = vec![0u8; pad2.virtual_size as usize];
// mem.read_raw_into(nt.base + pad2.virtual_address as usize, &mut pad2_raw[..])
//     .unwrap();

// let mut pad3_raw = vec![0u8; pad3.virtual_size as usize];
// mem.read_raw_into(nt.base + pad3.virtual_address as usize, &mut pad3_raw[..])
//     .unwrap();

// let free_rx = (nt.base
//     + pad2_raw
//         .windows(stub.len() + 32)
//         .position(|w| w.iter().all(|b| *b == 0xCC))
//         .unwrap())
// .as_mem_aligned(16)
// .to_umem() as usize
//     + 16;

// let free_rw = (nt.base
//     + pad3_raw
//         .windows(size_of::<CallArgs>() + size_of::<usize>() * 2)
//         .position(|w| w.iter().all(|b| *b == 0xCC))
//         .unwrap())
// .as_mem_aligned(size_of::<usize>() as u64)
// .to_umem() as usize
//     + size_of::<usize>();

// let mut args = CallArgs {
//     args: [0x80 | 0x8, 64, 0x656E6F4E, 0],
//     target: ex_allocate_pool_2,
//     retval: 0,
//     done: false,
// };

// // place hook in frequently called kernel callback/function
// // let exp_create_worker_thread = nt.base.to_umem() as usize + 0x270DE0;

// // let mut backup_bytes: [u8; 5] = [0u8; 5];
// // mem.read_raw_into(exp_create_worker_thread.into(), &mut backup_bytes[..])
// //     .unwrap();

// // load call data address
// stub[(0xA + 0x3)..(0xA + 0x3 + size_of::<i32>())].copy_from_slice(
//     &(free_rw.wrapping_sub(free_rx + 0xA + 0x7) as isize as i32).to_le_bytes(),
// );
// // load return value address
// stub[(0x2C + 0x3)..(0x2C + 0x3 + size_of::<i32>())].copy_from_slice(
//     &((free_rw + size_of::<usize>() * 5).wrapping_sub(free_rx + 0x2C + 0x7) as isize as i32)
//         .to_le_bytes(),
// );
// // redo original operation replaced by our hook before return back
// // let stublen = stub.len();
// // stub[(stublen - 1 - backup_bytes.len())..(stublen - 1)].copy_from_slice(&backup_bytes[..]);

// // write call arguments
// mem.write_raw(free_rw.into(), unsafe {
//     core::slice::from_raw_parts(
//         &raw const args as *const _ as *const u8,
//         size_of::<CallArgs>(),
//     )
// })
// .unwrap();

// // write shellcode
// mem.write_raw(free_rx.into(), &stub[..]).unwrap();

// // let mut hook: [u8; 5] = [0xE8, 0x0, 0x0, 0x0, 0x0];
// // hook[1..(1 + size_of::<i32>())].copy_from_slice(
// //     &(free_rx.wrapping_sub(exp_create_worker_thread + backup_bytes.len()) as i32).to_le_bytes(),
// // );
// // mem.write_raw(exp_create_worker_thread.into(), &hook[..])
// //     .unwrap();

// println!("Shellcode at {:X}", free_rx);
// println!("Call data at {:X}", free_rw);

// let backup_hal_ptr = mem.read::<usize>(hal_fn_ptr.into()).unwrap();
// println!("Backup HAL ptr {:X}", backup_hal_ptr);
// mem.write::<usize>(hal_fn_ptr.into(), &free_rx).unwrap();
// println!("Hooked at {:X}", hal_fn_ptr);

// println!("Waiting for execution...");

// // wait for hook execution to finish
// loop {
//     mem.read_raw_into(free_rw.into(), unsafe {
//         core::slice::from_raw_parts_mut(
//             &raw mut args as *mut _ as *mut u8,
//             size_of::<CallArgs>(),
//         )
//     })
//     .unwrap();

//     // dbg!(&args);

//     if args.done {
//         break;
//     }

//     sleep(Duration::from_millis(5));
// }

// sleep(Duration::from_millis(50));

// println!("RET: {:X}", args.retval);

// // unhook
// println!("Unhooking...");
// mem.write::<usize>(hal_fn_ptr.into(), &backup_hal_ptr)
//     .unwrap();
// // mem.write_raw(exp_create_worker_thread.into(), &backup_bytes[..])
// //     .unwrap();

// sleep(Duration::from_millis(50));

// // restore original bytes
// println!("Restoring original unused region...");
// stub.fill(0xCC);
// unsafe {
//     core::slice::from_raw_parts_mut(&raw mut args as *mut _ as *mut u8, size_of::<CallArgs>())
//         .fill(0xCC);
// }

// mem.write_raw(free_rx.into(), &stub[..]).unwrap();
// mem.write_raw(free_rw.into(), unsafe {
//     core::slice::from_raw_parts(
//         &raw const args as *const _ as *const u8,
//         size_of::<CallArgs>(),
//     )
// })
// .unwrap();

// sleep(Duration::from_millis(50));

// for s in pe.section_table {
//     dbg!(s.get_name());
// }

// nt.base

// let qpc = os
//     .module_export_by_name(&nt, "KeQueryPerformanceCounter")
//     .unwrap();

// let mut swap_pa: usize = 0;
// let mut swap_va: usize = 0;
//
// {
//     let mut translator = os.as_mut_impl_virtualtranslate().unwrap();

//     for pa in (0x0..0x10_000).step_by(0x1000) {
//         if let Some(va) = translator.phys_to_virt(pa.into()) {
//             let info = translator.virt_page_info(va).unwrap();

//             if info.is_valid() {
//                 let pt = info.page_type;

//                 swap_va = va.to_umem() as usize;
//                 swap_pa = pa;

//                 println!("{pa:X} => {va:X}, {pt:?}");

//                 break;
//             }
//         }
//     }

//     if swap_va == 0 {
//         return;
//     }
// }

// let qpc_bytes = mem.read::<[u8; 64]>(nt.base + qpc.offset).unwrap();
// // mov rsi, cs:HalpPerformanceCounter
// let offset_to_load_qpc_instr = qpc_bytes
//     .windows(3)
//     .enumerate()
//     .find(|(i, c)| *c == [0x48, 0x8B, 0x35])
//     .unwrap()
//     .0;
// let instr = nt.base + qpc.offset + offset_to_load_qpc_instr;
// let rel32_off = mem.read::<i32>(instr + 0x3).unwrap() as isize;
// let halp_performance_counter_ptr = (instr + 0x7) + rel32_off;
// let halp_performance_counter = mem.read::<usize>(halp_performance_counter_ptr).unwrap();

// let hpc_type_ptr = halp_performance_counter + 0xE4;
// let hpc_type = mem.read::<i32>(hpc_type_ptr.into()).unwrap();

// let query_counter_routine_ptr = halp_performance_counter + 0x70;
// let query_counter_routine = mem.read::<usize>(query_counter_routine_ptr.into()).unwrap();

// let b = swap_va;

// let data = mem.read::<[u8; 0x1000]>(b.into()).unwrap();

// // sub rsp, 0x28
// // cmp qword ptr [rip+data], 0
// // jne done
// // movabs rcx, 0xCCCCCCCCCCCCCCCC
// // movabs rdx, 0xCCCCCCCCCCCCCCCC
// // movabs r8, 0xCCCCCCCCCCCCCCCC
// // movabs r9, 0xCCCCCCCCCCCCCCCC
// // movabs rax, 0xCCCCCCCCCCCCCCCC
// // call rax
// // mov [rip+data], rax
// // done:
// // add rsp, 0x28
// // xor rax, rax
// // ret
// // data:
// const SHELLCODE: [u8; 81] = [
//     0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0x3D, 0x45, 0x00, 0x00, 0x00, 0x00, 0x75, 0x3B, 0x48,
//     0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0xBA, 0xCC, 0xCC, 0xCC, 0xCC,
//     0xCC, 0xCC, 0xCC, 0xCC, 0x49, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x49,
//     0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,
//     0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0xD0, 0x48, 0x89, 0x05, 0x08, 0x00, 0x00, 0x00, 0x48, 0x83,
//     0xC4, 0x28, 0x48, 0x31, 0xC0, 0xC3,
// ];

// let free_region = (b
//     + data
//         .windows(SHELLCODE.len())
//         .position(|w| w == [0u8; SHELLCODE.len()])
//         .unwrap()
//     + 32)
//     & !0xF;

// // write shellcode
// mem.write(free_region.into(), &SHELLCODE).unwrap();

// let rcx: usize = 0x80;
// let rdx: usize = 64;
// let r8: usize = u32::from_le_bytes(*b"None") as usize;
// let r9: usize = 0x0;
// let call_target: usize = (nt.base.to_umem() + ex_allocate_pool.offset.to_umem()) as usize;

// println!("TARGET: 0x{call_target:X}");

// // write call args into shellcode
// mem.write((free_region + 0xE + 0x2).into(), &rcx).unwrap();
// mem.write((free_region + 0x18 + 0x2).into(), &rdx).unwrap();
// mem.write((free_region + 0x22 + 0x2).into(), &r8).unwrap();
// mem.write((free_region + 0x2C + 0x2).into(), &r9).unwrap();
// mem.write((free_region + 0x36 + 0x2).into(), &call_target)
//     .unwrap();

// // hook query ptr
// mem.write(hpc_type_ptr.into(), &5i32).unwrap();
// mem.write(query_counter_routine_ptr.into(), &free_region)
//     .unwrap();

// // wait for return value
// let mut retval: usize = 0;

// loop {
//     retval = mem.read((free_region + SHELLCODE.len()).into()).unwrap();

//     if retval != 0 {
//         break;
//     }

//     sleep(Duration::from_millis(1));
// }

// // restore query ptr/unhook
// mem.write(hpc_type_ptr.into(), &hpc_type).unwrap();
// mem.write(query_counter_routine_ptr.into(), &query_counter_routine)
//     .unwrap();

// sleep(Duration::from_millis(50));

// // cleanup shellcode
// // zero shellcode + return value
// mem.write(
//     free_region.into(),
//     &[0u8; SHELLCODE.len() + size_of::<usize>()],
// )
// .unwrap();

// println!("Allocated memory @ 0x{retval:X}");

// dbg!(zero_area_pos);

// let pte_base = 0xFFFFF68000000000..0xFFFFF6FFFFFFFFFF;

// let new_val: usize = 0;
// let new_hpc_type: i32 = 5;
// mem.write(hpc_type_ptr.into(), &new_hpc_type).unwrap();
// mem.write(query_counter_routine_ptr.into(), &new_val)
//     .unwrap();

// let off = query_counter_routine - nt.base.to_umem() as usize;

// println!("{off:X}");

// println!("{instr:X} {halp_performance_counter:X} {hpc_type:X} {query_counter_routine:#X?}");

// let processes = os.process_info_list().unwrap();
// let sys_proc = processes.iter().find(|p| p.pid == 4).unwrap();

// dbg!(sys_proc);

// let dtb = sys_proc.dtb1;
// let base = sys_proc.address.to_umem();

// let phys = os.into_phys_view();

// return;
