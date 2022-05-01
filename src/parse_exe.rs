
//use goblin::{error, Object};
use object::{Object, ObjectSection, ObjectSymbol};
use object::read::SectionIndex;

// I'd prefer the BTreeMap, but we're only hashing SectionIndex's
// which implement Hash but not Ord. Of course we could just get at the underlying usize field in them,
// but I've already taken the time the write out this comment explaining my decision so it's now final
use std::collections::HashMap;
//use std::collections::BTreeMap;


use crate::exec_mem::ExecPage;


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
			
			let section_data = section.data().expect("could not get data for section");
			//println!("Section {:?} data {:?}", section, section_data);
			bytes_loaded_into_memory.extend_from_slice(section_data);
		}
		//println!("section addr {} {:?}", section.address(), section);
	}

	let mut chk_stk_file_offset = None;

	for symbol in obj_file.symbols() {
		if symbol.name().expect("") == "__chkstk" {
			// We have a stack-check, so we want to insert an empty function body, and have all calls link to that instead
			// This isn't ideal, since in theory the compiler could mis-optimize a stack memory access, and we wouldn't catch it
			// However given that we're running this in our own process anyway, we kinda just assume that that doesn't happen
			chk_stk_file_offset = Some(bytes_loaded_into_memory.len());
			bytes_loaded_into_memory.push(0xc3);
		}
	}
	
	if let Some(section) = obj_file.section_by_name(".text") {
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
								if let Some(target_symbol_section_index) = target_symbol.section_index() {
									let target_section = obj_file.section_by_index(target_symbol_section_index).unwrap();
									let encoding = reloc.encoding();
									let reloc_size = reloc.size() as usize;
									if encoding == object::RelocationEncoding::Generic {
										let reloc_section_offset_in_memory = section_to_memory_addr.get(&target_section.index()).unwrap();
										let reloc_offset_in_memory = (reloc_section_offset_in_memory + target_symbol.address() as usize) as i64;
										let reloc_insert_offset_in_memory = (text_offset_in_memory + reloc_addr as usize) as i64;
										
										// TODO: oh, is the implicit addend the "add with what's already there"? and the addend is added either way?
										let addend = if reloc.has_implicit_addend() { reloc.addend() } else { 0 };
										let reloc_relative_offset = reloc_offset_in_memory - reloc_insert_offset_in_memory + addend;
										exec_page.fix_up_redirect(reloc_insert_offset_in_memory as usize, reloc_size, reloc_relative_offset);
									}
									else {
										panic!("bad relocation encoding");
									}
								}
								else if target_symbol.name().expect("") == "__chkstk" {
									// TODO: Some code dup with above
									let encoding = reloc.encoding();
									let reloc_size = reloc.size() as usize;
									if encoding == object::RelocationEncoding::Generic {
										let reloc_offset_in_memory = (chk_stk_file_offset.unwrap()) as i64;
										let reloc_insert_offset_in_memory = (text_offset_in_memory + reloc_addr as usize) as i64;
										// TODO: wait do we need the addend?
										let addend = if reloc.has_implicit_addend() { reloc.addend() } else { 0 };
										let reloc_relative_offset = reloc_offset_in_memory - reloc_insert_offset_in_memory + addend;
										exec_page.fix_up_redirect(reloc_insert_offset_in_memory as usize, reloc_size, reloc_relative_offset);
									}
									else {
										panic!("bad relocation encoding");
									}
								}
								else {
									println!("symbol had no section index, and is not __chkstk {:?}", target_symbol);
									panic!("cannot relocate symbol");
								}
							}
							_ => { panic!("Bad reloc target type"); }
						}
					}
					// TODO:
					// thread 'main' panicked at
					// 'Bad relocation kind Relocation { kind: Elf(275), encoding: Generic, size: 0, target: Symbol(SymbolIndex(3)), addend: 0, implicit_addend: false }', src\parse_exe.rs:115:25
					else {
						panic!("Bad relocation kind {:?}", reloc);
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
