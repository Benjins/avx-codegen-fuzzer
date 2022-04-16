
//use goblin::{error, Object};
use object::{Object, ObjectSection, ObjectSymbol};

use executable_memory::ExecutableMemory;

use core::arch::x86_64::__m256i;
use core::arch::x86_64::__m128i;


// Bah....
//impl Clone for ExecutableMemory {
//	fn clone(&self) -> ExecutableMemory {
//		
//	}
//
//	//fn clone_from(&mut self, source: &ExecutableMemory) {
//	//	
//	//}
//}


// TODO: Make it generic so that the function pointer, input types, etc. can vary?
//#[derive(Clone)]
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


pub fn parse_obj_file(bin_data : &[u8], func_name : &str) -> Option<ExecPage> {
	let obj_file = object::File::parse(bin_data).expect("");
	if let Some(section) = obj_file.section_by_name(".text") {
		let data = section.data().expect("");
		for symbol in obj_file.symbols() {
			let symbol_name = symbol.name().expect("");
			if symbol_name == func_name {
				let addr = symbol.address() as usize;
				//let size = symbol.size() as usize;
				//println!("Lookup in .text of symbol do_stuff_2 ({} bytes): {:#x?}", size, &data[addr..]);
				
				let mut exec_page = ExecPage::new(5);
				exec_page.load_with_code(&data[..], addr);
				return Some(exec_page);
			}
		}
	} else {
		eprintln!("section not available");
	}
	
	return None;
}






//pub fn get_func_code_bytes(exe_buffer : &Vec<u8>, func_name : &str) -> Vec<u8> {
//	let obj_file = object::File::parse(&**exe_buffer).unwrap();
//	println!("obj_file = {:?}", obj_file);
//	
//	//if let Some(section) = obj_file.section_by_name(".boot") {
//	//	println!("{:#x?}", section.data()?);
//	//} else {
//	//	eprintln!("section not available");
//	//}
//	
//	return Vec::<u8>::new();
//}

//pub fn get_func_code_bytes(exe_buffer : &Vec<u8>, func_name : &str) -> Vec<u8> {
//	match Object::parse(exe_buffer).unwrap() {
//		Object::Elf(elf) => {
//			println!("elf: {:#?}", &elf);
//		},
//		Object::PE(pe) => {
//			println!("pe: {:#?}", &pe);
//		},
//		Object::Unknown(magic) => { panic!("unknown magic: {:#x}", magic) },
//		_ => { panic!("Unknown exe file type"); }
//	}
//
//	return Vec::<u8>::new();
//}
