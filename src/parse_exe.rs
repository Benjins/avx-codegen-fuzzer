
//use goblin::{error, Object};
use object::{Object, ObjectSection, ObjectSymbol};
use object::read::SectionIndex;

// I'd prefer the BTreeMap, but we're only hashing SectionIndex's
// which implement Hash but not Ord. Of course we could just get at the underlying usize field in them,
// but I've already taken the time the write out this comment explaining my decision so it's now final
use std::collections::HashMap;
//use std::collections::BTreeMap;

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
	
	pub fn fix_up_redirect(&mut self, write_offset : usize, write_len_bits : usize, value : i64) {
		assert!(write_len_bits % 8 == 0);
		let value_bytes = value.to_le_bytes();
		let write_len_bytes = write_len_bits / 8;
		
		//println!("Fix up redirect at offset {}, {} bytes. Currently {:?}, will be {:?}",
		//	write_offset,
		//	write_len_bytes,
		//	&self.page[write_offset..write_offset+write_len_bytes],
		//	&value_bytes[..write_len_bytes]);

		self.page[write_offset..write_offset+write_len_bytes].clone_from_slice(&value_bytes[..write_len_bytes]);
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

//fn get_symbol_by_inde

// For now just uses zero as a placeholder, idk if anything cares
fn align_vec(vec : &mut Vec<u8>, alignment : usize) {
	let byte_offset = vec.len() % alignment;
	if byte_offset > 0 {
		for _ in byte_offset..alignment {
			vec.push(0);
		}
	}
}

pub fn parse_obj_file(bin_data : &[u8], func_name : &str) -> Option<ExecPage> {
	let obj_file = object::File::parse(bin_data).expect("");
	
	let mut bytes_loaded_into_memory = Vec::<u8>::with_capacity(16*1024);
	let mut section_to_memory_addr = HashMap::<SectionIndex, usize>::new();
	
	for section in obj_file.sections() {
		if section.size() > 0 {
			align_vec(&mut bytes_loaded_into_memory, section.align() as usize);
			section_to_memory_addr.insert(section.index(), bytes_loaded_into_memory.len());
			bytes_loaded_into_memory.extend_from_slice(section.data().expect("could not get data for section"));
		}
		//println!("section addr {} {:?}", section.address(), section);
	}
	
	if let Some(section) = obj_file.section_by_name(".text") {
		let (text_start_in_file, text_end_in_file) = section.file_range().unwrap();
		//println!(".text file range: {}-{}", text_start_in_file, text_end_in_file);
		//for reloc in section.relocations() {
		//	println!(".text relocation: {:?}", reloc);
		//}
		//for symbol in obj_file.symbols() {
		//	println!(".text symbol {:?} {:?}", symbol, symbol.index());
		//}
		
		let data = section.data().expect("");
		for symbol in obj_file.symbols() {
			let symbol_name = symbol.name().expect("");
			if symbol_name == func_name {
				let addr = symbol.address() as usize;
				//let size = symbol.size() as usize;
				//println!("Lookup in .text of symbol do_stuff_2 ({} bytes): {:#x?}", size, &data[addr..]);
				
				let mut exec_page = ExecPage::new(5);
				// TODO: alignment of sections that need it
				let text_offset_in_memory = section_to_memory_addr.get(&section.index()).unwrap();
				exec_page.load_with_code(&bytes_loaded_into_memory[..], *text_offset_in_memory + addr);
				
				for (reloc_addr, reloc) in section.relocations() {
					if reloc.kind() == object::RelocationKind::Relative {
						let reloc_target = reloc.target();
						match reloc_target {
							object::read::RelocationTarget::Symbol(reloc_target_symbol_index) => {
								let target_symbol = obj_file.symbol_by_index(reloc_target_symbol_index).expect("bad symbol index");
								let target_section = obj_file.section_by_index(target_symbol.section_index().unwrap()).unwrap();
								let encoding = reloc.encoding();
								let reloc_size = reloc.size() as usize;
								if encoding == object::RelocationEncoding::Generic {
									let reloc_section_offset_in_memory = section_to_memory_addr.get(&target_section.index()).unwrap();
									let reloc_offset_in_memory = (reloc_section_offset_in_memory + target_symbol.address() as usize) as i64;
									let reloc_insert_offset_in_memory = (text_offset_in_memory + reloc_addr as usize) as i64;
									let addend = if reloc.has_implicit_addend() { reloc.addend() } else { 0 };
									let reloc_relative_offset = reloc_offset_in_memory - reloc_insert_offset_in_memory + addend;
									exec_page.fix_up_redirect(reloc_insert_offset_in_memory as usize, reloc_size, reloc_relative_offset);
								}
								else {
									panic!("bad relocation encoding");
								}
							}
							_ => { panic!("Bad reloc target type"); }
						}
					}
					else {
						panic!("Bad relocation kind");
					}
				}
				
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
