use std::{thread::sleep, time::Duration};

use memflow::prelude::v1::*;
use pe_parser::pe::parse_portable_executable;

// for 5 tables u just get a 5th table offset by getting the next 9 bits in the address.
// u should first check if it's even doing 5 page table addressing by checking if bit 12 is set in cr4

pub fn find_pattern(module: &str, section: &str, pattern: &[u8]) -> usize {
    let inventory = Inventory::scan();
    let conn = inventory.builder().connector("qemu");
    let mut os = conn
        .os("win32")
        .build()
        .expect("Failed to build OS connector");

    let nt = os.module_by_name(module).unwrap();
    let mut mem = os.cast_impl_memoryview().unwrap();

    let mut nt_hdr = vec![0u8; 0x1000];
    mem.read_raw_into(nt.base, &mut nt_hdr[..]).unwrap();

    let pe = parse_portable_executable(&nt_hdr).unwrap();

    let sec = pe
        .section_table
        .iter()
        .find(|s| {
            s.get_name()
                .map(|s| s.trim_end_matches('\0').eq_ignore_ascii_case(section))
                == Some(true)
        })
        .unwrap();

    let mut sec_raw = vec![0u8; sec.virtual_size as usize];
    mem.read_raw_into(nt.base + sec.virtual_address as usize, &mut sec_raw[..])
        .unwrap();

    let occurence = (nt.base
        + sec.virtual_address
        + sec_raw
            .windows(pattern.len())
            .position(|w| w.iter().zip(pattern.iter()).all(|(a, b)| a == b))
            .unwrap());

    occurence.to_umem() as usize
}

pub fn get_module(module: &str) -> usize {
    let inventory = Inventory::scan();
    let conn = inventory.builder().connector("qemu");
    let mut os = conn
        .os("win32")
        .build()
        .expect("Failed to build OS connector");

    let nt = os.module_by_name(module).unwrap();

    nt.base.to_umem() as usize
}

pub fn get_proc_addr(module: &str, name: &str) -> usize {
    let inventory = Inventory::scan();
    let conn = inventory.builder().connector("qemu");
    let mut os = conn
        .os("win32")
        .build()
        .expect("Failed to build OS connector");

    let nt = os.module_by_name(module).unwrap();

    let export = os.module_export_by_name(&nt, name).unwrap();

    nt.base.to_umem() as usize + export.offset as usize
}

pub fn call_user_func(module: &str, name: &str, args: [usize; 4]) -> usize {
    let inventory = Inventory::scan();
    let conn = inventory.builder().connector("qemu");
    let mut os = conn
        .os("win32")
        .build()
        .expect("Failed to build OS connector");

    let processes = os.process_info_list().unwrap();

    for proc in processes {
        if proc.name.starts_with("steamwebhelper.exe") {
            if proc.pid != 0x14E0 {
                continue;
            }

            let mut proc = os.process_by_info(proc).unwrap();

            // let m = proc.module_list().unwrap();
            // for m in m {
            //     if m.name.contains("win32u") {
            //         println!("{m:X?}");
            //     }
            // }

            let mut op: Option<usize> = None;
            let mut wr_op: Option<usize> = None;
            let segments = proc.mapped_mem_vec(0);
            for segment in segments {
                if segment.2.contains(PageType::WRITEABLE)
                    && segment.2.contains(PageType::NOEXEC)
                    && segment.0.to_umem() < 0x7FFF00000000
                    && segment.0.to_umem() > 0x2FFF00000000
                    && wr_op.is_none()
                {
                    let mut seg = vec![0u8; segment.1 as usize];
                    proc.read_raw_into(segment.0, &mut seg[..]);

                    let offset = seg
                        .windows(64)
                        .position(|x| x.iter().all(|x| *x == 0))
                        .unwrap();
                    wr_op = Some((segment.0.to_umem() as usize + offset + 16) / 16 * 16);
                    // println!("{segment:?}");
                }

                if segment.2.contains(PageType::WRITEABLE)
                    && !segment.2.contains(PageType::NOEXEC)
                    // && segment.0.to_umem() < 0x7FFF00000000
                    && segment.0.to_umem() < 0x5FFF00000000
                    && segment.0.to_umem() > 0x100000000
                    && segment.1 > 0x3000
                    && op.is_none()
                {
                    let mut seg = vec![0u8; segment.1 as usize];
                    proc.read_raw_into(segment.0, &mut seg[..]);

                    if let Some(offset) = seg
                        .windows(90 + 16 * 2)
                        .position(|x| x.iter().all(|x| *x == 0))
                    {
                        // println!("{:X}", segment.0);
                        op = Some((segment.0.to_umem() as usize + offset + 16) / 16 * 16);
                    }
                    // println!("{segment:?}");
                }

                // println!("{segment:?}");
            }

            println!("{:X?} {:X?}", wr_op, op);

            // continue;

            let m = proc.module_by_name("user32.dll").unwrap();
            let export = proc.module_export_by_name(&m, "Sleep").unwrap();
            let func = m.base + export.offset;

            println!("{export:X?}");

            let m = proc.module_by_name("kernel32.dll").unwrap();
            let va_export = proc.module_export_by_name(&m, "VirtualAlloc").unwrap();
            let va_func = m.base + va_export.offset;

            println!("{va_export:X?}");

            // push rbx
            // push r10
            // push r11
            // mov rbx, 0x91283910391031
            // cmp qword ptr[rbx], 0xFFFFFFFFFFFFFFFF
            // jne done
            // mov rax, 0x91283910391031
            // mov rcx, 0x91283910391031
            // mov rdx, 0x91283910391031
            // mov r8, 0x91283910391031
            // mov r9, 0x91283910391031
            // mov r10, 0x91283910391031
            // mov r11, 0x91283910391031
            // push r11
            // push r10
            // call rax
            // mov [rbx], rax
            // done:
            // pop r11
            // pop r10
            // pop rbx
            // push rbx
            // push rdi
            // push r14
            // jmp [rip+0x1231]
            let mut stub = [
                0x53, 0x41, 0x52, 0x41, 0x53, 0x48, 0xBB, 0x31, 0x10, 0x39, 0x10, 0x39, 0x28, 0x91,
                0x00, 0x48, 0x83, 0x3B, 0xFF, 0x75, 0x37, 0x48, 0xB8, 0x31, 0x10, 0x39, 0x10, 0x39,
                0x28, 0x91, 0x00, 0x48, 0xB9, 0x31, 0x10, 0x39, 0x10, 0x39, 0x28, 0x91, 0x00, 0x48,
                0xBA, 0x31, 0x10, 0x39, 0x10, 0x39, 0x28, 0x91, 0x00, 0x49, 0xB8, 0x31, 0x10, 0x39,
                0x10, 0x39, 0x28, 0x91, 0x00, 0x49, 0xB9, 0x31, 0x10, 0x39, 0x10, 0x39, 0x28, 0x91,
                0x00, 0xFF, 0xD0, 0x48, 0x89, 0x03, 0x41, 0x5B, 0x41, 0x5A, 0x5B, 0x53, 0x57, 0x41,
                0x56, 0xE9, 0x31, 0x12, 0x00, 0x00,
            ];

            unsafe {
                (stub.as_mut_ptr().add(0x5 + 0x2) as *mut usize).write_unaligned(wr_op.unwrap());
                (stub.as_mut_ptr().add(0x15 + 0x2) as *mut usize)
                    .write_unaligned(va_func.to_umem() as usize);
                (stub.as_mut_ptr().add(0x1F + 0x2) as *mut usize).write_unaligned(args[0]);
                (stub.as_mut_ptr().add(0x29 + 0x2) as *mut usize).write_unaligned(args[1]);
                (stub.as_mut_ptr().add(0x33 + 0x2) as *mut usize).write_unaligned(args[2]);
                (stub.as_mut_ptr().add(0x3D + 0x2) as *mut usize).write_unaligned(args[3]);
                // (stub.as_mut_ptr().add(0x47 + 0x2) as *mut usize).write_unaligned(args[4]);
                // (stub.as_mut_ptr().add(0x51 + 0x2) as *mut usize).write_unaligned(args[5]);

                let rel32_off = (func.to_umem() as usize + 0x5) as isize
                    - (op.unwrap() + stub.len() - 0x5 - 0x5) as isize;
                (stub.as_mut_ptr().add(0x55 + 0x1) as *mut i32).write_unaligned(rel32_off as i32);

                proc.write_raw(op.unwrap().into(), &stub[..]).unwrap();

                let rel32_off = op.unwrap() as isize - (func.to_umem() as usize - 0x5) as isize;
                let mut backup_stub1 = [0x00, 0x00, 0x00, 0x00, 0x00];
                let mut stub1 = [0xE9, 0x00, 0x00, 0x00, 0x00];

                (stub1.as_mut_ptr().add(0x1) as *mut i32).write_unaligned(rel32_off as i32);

                proc.read_raw_into(func, &mut backup_stub1[..]).unwrap();
                proc.write_raw(func, &mut stub1[..]).unwrap();

                proc.write(wr_op.unwrap().into(), &usize::MAX).unwrap();

                while proc.read::<usize>(wr_op.unwrap().into()).unwrap() == usize::MAX {}

                let alloc = proc.read::<usize>(wr_op.unwrap().into()).unwrap();
                println!("{alloc:X}");

                stub.fill(0);
                proc.write_raw(op.unwrap().into(), &stub[..]).unwrap();
                proc.write(wr_op.unwrap().into(), &0usize).unwrap();

                return 0;
            }
        }
    }

    0
}

pub fn call_func(func: usize, args: [usize; 4]) -> usize {
    loop {
        let inventory = Inventory::scan();
        let conn = inventory.builder().connector("qemu");
        let mut os = conn
            .os("win32")
            .build()
            .expect("Failed to build OS connector");

        let nt = os.module_by_name("ntoskrnl.exe").unwrap();

        let ke_query_auxiliary_counter_frequency = os
            .module_export_by_name(&nt, "KeQueryAuxiliaryCounterFrequency")
            .unwrap();

        let mov_rax_ptr =
            (nt.base + ke_query_auxiliary_counter_frequency.offset).to_umem() as usize + 0x4;

        let nt_add_atom = nt.base.to_umem() as usize
            + os.module_export_by_name(&nt, "KeDelayExecutionThread")
                .unwrap()
                .offset as usize;
        // let nt_add_atom = nt.base.to_umem() as usize + 0x405B40;

        let mut mem = os.cast_impl_memoryview().unwrap();

        let hal_fn_ptr = (mov_rax_ptr + 0x7).wrapping_add_signed(i32::from_ne_bytes(
            mem.read::<[u8; 4]>((mov_rax_ptr + 0x3).into()).unwrap(),
        ) as isize);

        let mut nt_hdr = vec![0u8; 0x1000];
        mem.read_raw_into(nt.base, &mut nt_hdr[..]).unwrap();

        let pe = parse_portable_executable(&nt_hdr).unwrap();

        let pad2 = pe
            .section_table
            .iter()
            .find(|s| s.name.starts_with(b"Pad2"))
            .unwrap();
        let pad3 = pe
            .section_table
            .iter()
            .find(|s| s.name.starts_with(b"Pad3"))
            .unwrap();

        let mut pad2_raw = vec![0u8; pad2.virtual_size as usize];
        mem.read_raw_into(nt.base + pad2.virtual_address as usize, &mut pad2_raw[..])
            .unwrap();

        let mut pad3_raw = vec![0u8; pad3.virtual_size as usize];
        mem.read_raw_into(nt.base + pad3.virtual_address as usize, &mut pad3_raw[..])
            .unwrap();

        // cli
        // mov rax, cr8
        // pushfq
        // push rax
        // push rbx
        // push rcx
        // push rdx
        // push r8
        // push r9
        // mov rax, 0xF
        // mov cr8, rax
        // sub rsp, 0x48
        // xor rax, rax
        // mov ax, cs
        // and ax, 3
        // cmp ax, 0
        // jne done
        // movabs rax, 0xCCCCCCCCCCCCCCCC
        // cmp byte ptr[rax+8], 1
        // jne do
        // jmp done
        // do:
        // mov byte ptr[rax+8], 1
        // mov rcx, [rax+8*2]
        // mov rdx, [rax+8*3]
        // mov r8, [rax+8*4]
        // mov r9, [rax+8*5]
        // mov [rsp+0x80+0x8], rax
        // call qword ptr[rax]
        // xchg [rsp+0x80+0x8], rax
        // mov [rsp+0x80+0x8*2], rbx
        // mov rbx, [rsp+0x80+0x8]
        // mov [rax+8*6], rbx
        // mov rbx, [rsp+0x80+0x8*2]
        // done:
        // add rsp, 0x48
        // pop r9
        // pop r8
        // pop rdx
        // pop rcx
        // pop rbx
        // pop rax
        // popfq
        // mov cr8, rax
        // xor rax, rax
        // sti
        // sfence
        // ret
        let mut stub = [
            0xFA, 0x44, 0x0F, 0x20, 0xC0, 0x9C, 0x50, 0x53, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51,
            0x48, 0xC7, 0xC0, 0x0F, 0x00, 0x00, 0x00, 0x44, 0x0F, 0x22, 0xC0, 0x48, 0x83, 0xEC,
            0x48, 0x48, 0x31, 0xC0, 0x66, 0x8C, 0xC8, 0x66, 0x83, 0xE0, 0x03, 0x66, 0x83, 0xF8,
            0x00, 0x75, 0x54, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x80,
            0x78, 0x08, 0x01, 0x75, 0x02, 0xEB, 0x42, 0xC6, 0x40, 0x08, 0x01, 0x48, 0x8B, 0x48,
            0x10, 0x48, 0x8B, 0x50, 0x18, 0x4C, 0x8B, 0x40, 0x20, 0x4C, 0x8B, 0x48, 0x28, 0x48,
            0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0xFF, 0x10, 0x48, 0x87, 0x84, 0x24, 0x88,
            0x00, 0x00, 0x00, 0x48, 0x89, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x9C,
            0x24, 0x88, 0x00, 0x00, 0x00, 0x48, 0x89, 0x58, 0x30, 0x48, 0x8B, 0x9C, 0x24, 0x90,
            0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x48, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x5B,
            0x58, 0x9D, 0x44, 0x0F, 0x22, 0xC0, 0x48, 0x31, 0xC0, 0xFB, 0x0F, 0xAE, 0xF8, 0xC3,
        ];

        #[repr(C)]
        #[derive(PartialEq, Default, Pod)]
        pub struct StubData {
            pub retval: usize,
            pub done: usize,
            pub args: [usize; 4],
            pub result: usize,
        }

        let mut data = StubData {
            retval: func,
            done: 0,
            args,
            result: 0,
        };

        let free_rx = (nt.base
            + pad2.virtual_address
            + pad2_raw
                .windows(stub.len() + size_of::<usize>() * 2)
                .position(|w| w.iter().all(|b| *b == 0x00))
                .unwrap())
        .as_mem_aligned(size_of::<usize>() as u64 * 2)
        .to_umem() as usize
            + size_of::<usize>();

        let free_rw = (nt.base
            + pad3.virtual_address
            + pad3_raw
                .windows(size_of::<StubData>() + size_of::<usize>() * 2)
                .position(|w| w.iter().all(|b| *b == 0x00))
                .unwrap())
        .as_mem_aligned(size_of::<usize>() as u64)
        .to_umem() as usize
            + size_of::<usize>();

        mem.write_raw(free_rw.into(), unsafe {
            core::slice::from_raw_parts(
                &raw const data as *const _ as *const u8,
                size_of::<StubData>(),
            )
        })
        .unwrap();

        // println!("{:X}", data.retval);

        stub[(0x2d + 2)..(0x2d + 2 + 8)].copy_from_slice(&free_rw.to_le_bytes());

        // let dsp = ((nt_add_atom + 0x5) as isize - (free_rx + 0x89 + 0x5) as isize) as i32;
        // stub[(0x89 + 1)..(0x89 + 1 + 0x4)].copy_from_slice(&dsp.to_le_bytes());

        mem.write(free_rx.into(), &stub).unwrap();

        let mut jmp = [0xe9, 0xcc, 0xcc, 0xcc, 0xcc];
        let dsp = (free_rx as isize - (nt_add_atom + 0x5) as isize) as i32;
        jmp[1..(1 + 4)].copy_from_slice(&dsp.to_le_bytes());

        let bk = mem.read::<[u8; 5]>(nt_add_atom.into()).unwrap();

        // println!("stub: {:X}", free_rx);

        // std::io::stdin().read_line(&mut String::new());

        mem.write(nt_add_atom.into(), &jmp).unwrap();

        // wait for hook execution to finish
        loop {
            let data = mem.read::<StubData>(free_rw.into()).unwrap();

            if data.done != 0 {
                break;
            }
        }

        sleep(Duration::from_millis(50));

        let data = mem.read::<StubData>(free_rw.into()).unwrap();

        sleep(Duration::from_millis(5));

        mem.write(nt_add_atom.into(), &bk).unwrap();

        sleep(Duration::from_millis(50));

        mem.write(free_rw.into(), &StubData::default()).unwrap();
        stub.fill(0);
        mem.write(free_rx.into(), &stub).unwrap();

        return data.result;
    }
}
