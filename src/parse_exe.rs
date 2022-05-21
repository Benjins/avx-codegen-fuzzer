
//use goblin::{error, Object};
use object::{Object, ObjectSection, ObjectSymbol};
use object::read::SectionIndex;

// I'd prefer the BTreeMap, but we're only hashing SectionIndex's
// which implement Hash but not Ord. Of course we could just get at the underlying usize field in them,
// but I've already taken the time the write out this comment explaining my decision so it's now final
use std::collections::HashMap;
use std::collections::BTreeSet;
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

// TODO: Do the same for Linux/etc.

#[cfg(target_os = "windows")]
const MEMSET_x86_BYTES : [u8 ; 28] = [
  0x48, 0x89, 0xc8,                    // mov    %rcx,%rax
  0x4d, 0x85, 0xc0,                    // test   %r8,%r8
  0x74, 0x13,                          // je     1b <?my_memset@@YAPEAXPEAXH_K@Z+0x1b>
  0x31, 0xc9,                          // xor    %ecx,%ecx
  0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,  // nopw   0x0(%rax,%rax,1)
  0x88, 0x14, 0x08,                    // mov    %dl,(%rax,%rcx,1)
  0x48, 0xff, 0xc1,                    // inc    %rcx
  0x49, 0x39, 0xc8,                    // cmp    %rcx,%r8
  0x75, 0xf5,                          // jne    10 <?my_memset@@YAPEAXPEAXH_K@Z+0x10>
  0xc3                                 // retq
];

pub fn parse_obj_file(bin_data : &[u8], func_name : &str) -> Option<ExecPage> {
	let obj_file = object::File::parse(bin_data).expect("");
	
	let mut bytes_loaded_into_memory = Vec::<u8>::with_capacity(16*1024);
	let mut section_to_memory_addr = HashMap::<SectionIndex, usize>::new();
	
	let forbidden_sections = {
		let mut forbidden_sections = BTreeSet::new();
		forbidden_sections.insert(".comment");

		forbidden_sections
	};
	
	for section in obj_file.sections() {
		let section_name = section.name();
		if section.size() > 0 && (section_name.is_err() || !forbidden_sections.contains(section_name.unwrap())) {
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
			break;
		}
	}

	let mut memset_file_offset = None;
	for symbol in obj_file.symbols() {
		if symbol.name().expect("") == "memset" {
			memset_file_offset = Some(bytes_loaded_into_memory.len());
			bytes_loaded_into_memory.extend_from_slice(&MEMSET_x86_BYTES[..]);
		}
	}

	if let Some(section) = obj_file.section_by_name(".text") {
		for symbol in obj_file.symbols() {
			let symbol_name = symbol.name().expect("");
			if symbol_name == func_name {
				let addr = symbol.address() as usize;
				let mut exec_page = ExecPage::new(16);
				let text_offset_in_memory = section_to_memory_addr.get(&section.index()).unwrap();
				exec_page.load_with_code(&bytes_loaded_into_memory[..], *text_offset_in_memory + addr);
				
				for (reloc_addr, reloc) in section.relocations() {
					match reloc.kind() {
						object::RelocationKind::Relative => {
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
											
											let addend = reloc.addend();
											let reloc_relative_offset = reloc_offset_in_memory - reloc_insert_offset_in_memory + addend;
											exec_page.fix_up_redirect(reloc_insert_offset_in_memory as usize, reloc_size, reloc_relative_offset, reloc.has_implicit_addend());
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
											let addend = reloc.addend();
											let reloc_relative_offset = reloc_offset_in_memory - reloc_insert_offset_in_memory + addend;
											exec_page.fix_up_redirect(reloc_insert_offset_in_memory as usize, reloc_size, reloc_relative_offset, reloc.has_implicit_addend());
										}
										else {
											panic!("bad relocation encoding");
										}
									}
									else if target_symbol.name().expect("") == "memset" {
										// TODO: Some code dup with above
										let encoding = reloc.encoding();
										let reloc_size = reloc.size() as usize;
										if encoding == object::RelocationEncoding::Generic {
											let reloc_offset_in_memory = (memset_file_offset.unwrap()) as i64;
											let reloc_insert_offset_in_memory = (text_offset_in_memory + reloc_addr as usize) as i64;
											// TODO: wait do we need the addend?
											let addend = reloc.addend();
											let reloc_relative_offset = reloc_offset_in_memory - reloc_insert_offset_in_memory + addend;
											exec_page.fix_up_redirect(reloc_insert_offset_in_memory as usize, reloc_size, reloc_relative_offset, reloc.has_implicit_addend());
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
						object::RelocationKind::Elf(extra_data) => {
							let reloc_target = reloc.target();
							match reloc_target {
								object::read::RelocationTarget::Symbol(reloc_target_symbol_index) => {
									let target_symbol = obj_file.symbol_by_index(reloc_target_symbol_index).expect("bad symbol index");
									let target_symbol_section = obj_file.section_by_index(target_symbol.section_index().unwrap()).expect("bad section index");

									let reloc_insert_offset_in_memory = (text_offset_in_memory + reloc_addr as usize) as i64;
									let reloc_section_offset_in_memory = section_to_memory_addr.get(&target_symbol_section.index()).unwrap();
									let reloc_offset_in_memory = (reloc_section_offset_in_memory + target_symbol.address() as usize) as i64 + reloc.addend();
									
									assert!(reloc.has_implicit_addend() == false);

									// ADRP page upper bits
									if extra_data == 275 {
										//let addend = ;
										let reloc_relative_offset = reloc_offset_in_memory - reloc_insert_offset_in_memory;
										let reloc_relative_offset_in_pages = reloc_relative_offset >> 12;
										exec_page.fix_up_arm_adrp_redirect(reloc_insert_offset_in_memory as usize, reloc_relative_offset_in_pages as i32);
									}
									// LDR offset
									else if extra_data == 299 {
										assert!(reloc_offset_in_memory >= 0);
										let reloc_offset_from_page_boundary = (reloc_offset_in_memory & 0xFFF);
										assert!(reloc_offset_from_page_boundary % 4 == 0);
										let encoded_reloc_offset_from_page = reloc_offset_from_page_boundary >> 2;
										exec_page.fix_up_arm_ldr_offset_redirect(reloc_insert_offset_in_memory as usize, encoded_reloc_offset_from_page as i32, 8);
									}
									// LDR offset for d* registers
									else if extra_data == 286 {
										assert!(reloc_offset_in_memory >= 0);
										let reloc_offset_from_page_boundary = (reloc_offset_in_memory & 0xFFF);
										assert!(reloc_offset_from_page_boundary % 8 == 0);
										let encoded_reloc_offset_from_page = reloc_offset_from_page_boundary >> 2;
										//println!("encoded_reloc_offset_from_page = {}", encoded_reloc_offset_from_page);
										exec_page.fix_up_arm_ldr_offset_redirect(reloc_insert_offset_in_memory as usize, encoded_reloc_offset_from_page as i32, 9);
									}
									// ADD immediate operand for adrp lower bits
									else if extra_data == 277 {
										//has_elf_reloc = true;
										
										assert!(reloc_offset_in_memory >= 0);
										let reloc_offset_from_page_boundary = (reloc_offset_in_memory & 0xFFF);
										assert!(reloc_offset_from_page_boundary % 8 == 0);
										
										exec_page.fix_up_arm_add_immediate(reloc_insert_offset_in_memory as usize, reloc_offset_from_page_boundary as i32);
									}
									else {
										std::fs::write("arm_reloc_unknown.elf", bin_data).expect("failed to write file");
										panic!("Unknown extra data {} in Elf arch-specific relocation", extra_data);
									}
								}
								_ => { panic!("Elf reloc with other target: {:?}", reloc_target); }
							}
						}
						_ => { panic!("Bad relocation kind {:?}", reloc); }
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

