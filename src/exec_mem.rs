

use executable_memory::ExecutableMemory;

use libc;

use std::convert::TryInto;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m128i, __m256i};

// :(
use crate::x86_intrinsics::AlignedWrapper;

#[derive(Debug)]
pub struct ExecPage {
	// TODO: See if this can be non-pub in some way for ARM
	pub page : ExecutableMemory,
	pub func_offset : usize,
	code_size : usize
}

impl ExecPage {
	pub fn new(num_pages : usize) -> ExecPage {
		return ExecPage { page: ExecutableMemory::new(num_pages), func_offset: 0, code_size: 0 }
	}

	pub fn load_with_code(&mut self, instructions : &[u8], func_offset : usize) {
		let num_bytes = instructions.len();
		self.page[..num_bytes].clone_from_slice(instructions);
		self.func_offset = func_offset;
		self.code_size = num_bytes;
	}
	
	pub fn fix_up_redirect(&mut self, write_offset : usize, write_len_bits : usize, value : i64, implicit_addend : bool) {
		assert!(write_len_bits % 8 == 0);
		let write_len_bytes = write_len_bits / 8;
		
		let current_value_bytes = &self.page[write_offset..write_offset+write_len_bytes];
		
		let current_value_int = {
			let mut current_value_byte_array = [0u8; 8];
			for (ii, val) in current_value_bytes.iter().enumerate() {
				current_value_byte_array[ii] = *val;
			}
			i64::from_le_bytes(current_value_byte_array)
		};

		let new_value = value + if implicit_addend { current_value_int } else { 0 };
		let new_value_bytes = new_value.to_le_bytes();
		self.page[write_offset..write_offset+write_len_bytes].clone_from_slice(&new_value_bytes[..write_len_bytes]);
	}
	
	// See https://developer.arm.com/documentation/ddi0596/2021-12/Base-Instructions/ADRP--Form-PC-relative-address-to-4KB-page-?lang=en
	pub fn fix_up_arm_adrp_redirect(&mut self, write_offset : usize, value : i32) {
		let current_value_bytes = &self.page[write_offset..write_offset+4];
		let current_value_int = i32::from_le_bytes(current_value_bytes.try_into().expect(""));

		let imm_lo = (value & 0x03); // bits [0:1]
		let imm_hi = (value >> 2) & ((1 << 17) - 1); // bits [2:19]

		let imm_lo_positioned = ((imm_lo as u32) << 29) as i32;
		let imm_hi_positioned = ((imm_hi as u32) << 5) as i32;

		let new_value_int = current_value_int | imm_lo_positioned | imm_hi_positioned;
		
		let new_value_bytes = new_value_int.to_le_bytes();
		self.page[write_offset..write_offset+4].clone_from_slice(&new_value_bytes[..]);
	}
	
	pub fn fix_up_arm_ldr_offset_redirect(&mut self, write_offset : usize, value : i32, shift : i32) {
		let current_value_bytes = &self.page[write_offset..write_offset+4];
		let current_value_int = i32::from_le_bytes(current_value_bytes.try_into().expect(""));
		assert!(value >= 0);
		let new_value_int = current_value_int | (value << shift);
		
		let new_value_bytes = new_value_int.to_le_bytes();
		self.page[write_offset..write_offset+4].clone_from_slice(&new_value_bytes[..]);
	}
	
	pub fn fix_up_arm_add_immediate(&mut self, write_offset : usize, value : i32) {
		let current_value_bytes = &self.page[write_offset..write_offset+4];
		let current_value_int = i32::from_le_bytes(current_value_bytes.try_into().expect(""));
		assert!(value >= 0);
		let new_value_int = current_value_int | (value << 10);
		
		let new_value_bytes = new_value_int.to_le_bytes();
		self.page[write_offset..write_offset+4].clone_from_slice(&new_value_bytes[..]);
	}

	pub fn flush_cache(&self) {
		#[cfg(target_arch = "aarch64")]
		{
			unsafe {
				let begin_ptr = self.page.as_ptr() as *mut libc::c_void;
				let end_ptr = self.page.as_ptr().offset(self.page.len() as isize) as *mut libc::c_void;

				__aarch64_sync_cache_range(begin_ptr, end_ptr);
			}
		}
	}
	
	#[cfg(target_arch = "x86_64")]
	pub fn execute_with_args_256i(&self, i_vals: &[i32], f_vals: &[f32], d_vals: &[f64]) -> __m256i {
		let func_ptr = unsafe { self.page.as_ptr().add(self.func_offset) };
		let func: unsafe extern "C" fn(*const i32, *const f32, *const f64) -> __m256i = unsafe { std::mem::transmute(func_ptr) };

		let ret = unsafe {
			func(i_vals.as_ptr(), f_vals.as_ptr(), d_vals.as_ptr())
		};

		return ret;
	}

	#[cfg(target_arch = "x86_64")]
	pub fn execute_with_args_128i(&self, i_vals: &[i32], f_vals: &[f32], d_vals: &[f64]) -> __m128i {
		let func_ptr = unsafe { self.page.as_ptr().add(self.func_offset) };
		let func: unsafe extern "C" fn(*const i32, *const f32, *const f64) -> __m128i = unsafe { std::mem::transmute(func_ptr) };

		let ret = unsafe {
			func(i_vals.as_ptr(), f_vals.as_ptr(), d_vals.as_ptr())
		};

		return ret;
	}
	
	pub fn execute_with_u32_io(&self, input: &[u32], output: &mut [u32]) {
		let func_ptr = unsafe { self.page.as_ptr().add(self.func_offset) };
		let func: unsafe extern "C" fn(*const u32, *mut u32) = unsafe { std::mem::transmute(func_ptr) };

		unsafe {
			func(input.as_ptr(), output.as_mut_ptr());
		}
	}
	
	pub fn execute_with_u64_io(&self, input: &[u64], output: &mut [u64]) {
		let func_ptr = unsafe { self.page.as_ptr().add(self.func_offset) };
		let func: unsafe extern "C" fn(*const u64, *mut u64) = unsafe { std::mem::transmute(func_ptr) };

		unsafe {
			func(input.as_ptr(), output.as_mut_ptr());
		}
	}
	
	pub fn get_bytes(&self) -> &[u8] {
		return &self.page[..self.code_size];
	}
	
	pub fn get_func_offset(&self) -> usize {
		return self.func_offset;
	}
}



//---------------------------------------------------------------------------------------
// Code ported from https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=libgcc/config/aarch64/sync-cache.c;h=41151e861d7fc32a77772b7f09b5f88779cbfd4c#l32

#[cfg(target_arch = "aarch64")]
const CTR_IDC_SHIFT : usize = 28;

#[cfg(target_arch = "aarch64")]
const CTR_DIC_SHIFT : usize = 29;

#[cfg(target_arch = "aarch64")]
unsafe fn __aarch64_sync_cache_range(base : *mut libc::c_void, end : *mut libc::c_void) {

    let mut cache_info : usize = 0;
    core::arch::asm!("mrs {}, ctr_el0", out(reg) cache_info);

    let icache_lsize = 4 << (cache_info & 0xF);
    let dcache_lsize = 4 << ((cache_info >> 16) & 0xF);

    let base = base as usize;
    let end = end as usize;

    if ((cache_info >> CTR_IDC_SHIFT) & 0x1) == 0x0 {
        let mut addr = base & !(dcache_lsize - 1);
        while addr < end {

            core::arch::asm! ("dc cvau, {}", in(reg) addr);

            addr += dcache_lsize;
        }
    }

    core::arch::asm! ("dsb ish");

    if ((cache_info >> CTR_DIC_SHIFT) & 0x1) == 0x0 {
        let mut addr = base & !(icache_lsize - 1);
        while addr < end {

            core::arch::asm! ("ic ivau, {}", in(reg) addr);

            addr += icache_lsize;
        }
    }

    core::arch::asm! ("isb");
}
//---------------------------------------------------------------------------------------

