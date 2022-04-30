

use executable_memory::ExecutableMemory;

use core::arch::x86_64::__m256i;
use core::arch::x86_64::__m128i;

#[derive(Debug)]
pub struct ExecPage {
	page : ExecutableMemory,
	func_offset : usize
}

impl ExecPage {
	pub fn new(num_pages : usize) -> ExecPage {
		return ExecPage { page: ExecutableMemory::new(num_pages), func_offset: 0 }
	}

	pub fn load_with_code(&mut self, instructions : &[u8], func_offset : usize) {
		let num_bytes = instructions.len();
		self.page[..num_bytes].clone_from_slice(instructions);
		self.func_offset = func_offset;
	}
	
	pub fn fix_up_redirect(&mut self, write_offset : usize, write_len_bits : usize, value : i64) {
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

		let new_value = value + current_value_int;
		let new_value_bytes = new_value.to_le_bytes();
		self.page[write_offset..write_offset+write_len_bytes].clone_from_slice(&new_value_bytes[..write_len_bytes]);
	}
	
	pub fn execute_with_args_256i(&self, i_vals: &[i32], f_vals: &[f32], d_vals: &[f64]) -> __m256i {
		let func_ptr = unsafe { self.page.as_ptr().add(self.func_offset) };
		let func: unsafe extern "C" fn(*const i32, *const f32, *const f64) -> __m256i = unsafe { std::mem::transmute(func_ptr) };

		let ret = unsafe {
			func(i_vals.as_ptr(), f_vals.as_ptr(), d_vals.as_ptr())
		};

		return ret;
	}

	pub fn execute_with_args_128i(&self, i_vals: &[i32], f_vals: &[f32], d_vals: &[f64]) -> __m128i {
		let func_ptr = unsafe { self.page.as_ptr().add(self.func_offset) };
		let func: unsafe extern "C" fn(*const i32, *const f32, *const f64) -> __m128i = unsafe { std::mem::transmute(func_ptr) };

		let ret = unsafe {
			func(i_vals.as_ptr(), f_vals.as_ptr(), d_vals.as_ptr())
		};

		return ret;
	}
}