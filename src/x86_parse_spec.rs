// This file parses out the Intel spec

use std::collections::{BTreeSet};

use crate::x86_intrinsics::*;

// You could previously download the XML-formatted spec here:
// https://software.intel.com/sites/landingpage/IntrinsicsGuide/files/data-3.6.0.xml
// archived here:
// https://web.archive.org/web/20211006023025id_/https://software.intel.com/sites/landingpage/IntrinsicsGuide/files/data-3.6.0.xml
// Intel seems to have moved it to here:
// https://www.intel.com/content/dam/develop/public/us/en/include/intrinsics-guide/data-3-6-0.xml
// which has been archived here:
// https://web.archive.org/web/20211024134604/https://www.intel.com/content/dam/develop/public/us/en/include/intrinsics-guide/data-3-6-0.xml
// These all seem to be the same. If the version changes, we might need to change the parsing code.
// But the archived versions should still work with this version of code

// Clang currently (as of Sept. 19, 2021) has a bug where it marks this opcode as commutative,
// but this leads to different results
// This was fixed in LLVM commit 391fa371fdfbc5ea4d4a924aebb27cb77d483da4
const MITIGATION_AVOID_VMPSADBW : bool = false;

// LLVM currently (as of Sept. 22, 2021) will crash if this op code is generated in a certain way
// creates a cycle in the DAG
// This was partially fixed in LLVM commit 468ff703e114599ce8fb7457bd3c7ef0b219e952, but can still lead to crashes
// Should now be fully fixed in LLVM commit 9452ec722ce0ba356a5ad178b0b1964ba8efb534
const MITIGATION_AVOID_PHADDW : bool = false;

// Integer-only ones should be less likely to have small, tolerated-in-spec differences that accumulate to large differences
// But, it means not testing some important code people care about, :shrugs:
const MITIGATION_AVOID_FLOATING_POINT_INTRINSICS : bool = true;

// For now, we don't properly implement the _MM_FROUND args, so skip these
const MITIGATION_AVOID_ROUNDING_INTRINSICS : bool = true;

// This is just permuting 32-bit elements, but it's listed as having floating point semantics but uses __m256i types,
// so overall kinda weird. Causes issues, unclear if bug
// UPDATE: Nope, not related to Permute, was instead an issue resolved in ed8dffef4c37d831a0bcc713ab56f38d8d9612df
const MITIGATION_AVOID_PERMUTR2F : bool = false;

// _mm256_alignr_epi8 according to the spec can take [0, 32) as its third arg, which defines a shift
// However, it's not clear if having it >16 will lead to 0's or UB. For now, we can disable it just in case
// pending an investigation (even if it is 0's it's a weird thing to do).
const ADJUST_ALIGNR_MASK_ARG : bool = false;

// MSVC doesn't have _mm_broadcastsi128_si256 ?
const MITIGATION_AVOID_VPBROADCAST : bool = true;

fn get_disallowed_intrinsics() -> BTreeSet<&'static str> {
	let mut disallowed_intrinsics = BTreeSet::<&'static str>::new();
	
	if MITIGATION_AVOID_VMPSADBW {
		disallowed_intrinsics.insert("_mm_mpsadbw_epu8");
		disallowed_intrinsics.insert("_mm256_mpsadbw_epu8");
	}
	
	if MITIGATION_AVOID_PHADDW {
		disallowed_intrinsics.insert("_mm_hadd_epi16");
		disallowed_intrinsics.insert("_mm_hadd_epi32");
		disallowed_intrinsics.insert("_mm_hsub_epi16");
		disallowed_intrinsics.insert("_mm_hsub_epi32");
	}

	if MITIGATION_AVOID_ROUNDING_INTRINSICS {
		disallowed_intrinsics.insert("_mm_round_sd");
		disallowed_intrinsics.insert("_mm_round_ss");

		disallowed_intrinsics.insert("_mm_round_pd");
		disallowed_intrinsics.insert("_mm_round_ps");

		disallowed_intrinsics.insert("_mm256_round_ps");
		disallowed_intrinsics.insert("_mm256_round_pd");
	}

	if MITIGATION_AVOID_VPBROADCAST {
		disallowed_intrinsics.insert("_mm_broadcastsi128_si256");
	}

	if MITIGATION_AVOID_PERMUTR2F {
		disallowed_intrinsics.insert("_mm256_permute2f128_si256");
	}

	// These all seem to leave some of the destination register undefined
	// In theory, we could try to generate code to clear those parts to some defined value,
	// or some other way of handling it. But for now, too complicated
	disallowed_intrinsics.insert("_mm256_undefined_ps");
	disallowed_intrinsics.insert("_mm256_undefined_pd");
	disallowed_intrinsics.insert("_mm256_undefined_si256");
	disallowed_intrinsics.insert("_mm256_castps128_ps256");
	disallowed_intrinsics.insert("_mm256_castpd128_pd256");
	disallowed_intrinsics.insert("_mm256_castsi128_si256");
	disallowed_intrinsics.insert("_mm_undefined_ps");
	disallowed_intrinsics.insert("_mm_undefined_pd");
	disallowed_intrinsics.insert("_mm_undefined_si128");

	// These ones are weird, and the types are weird
	// TODO: I think we can support them, but let's hold off for now
	disallowed_intrinsics.insert("_mm256_castsi128_si256");
	disallowed_intrinsics.insert("_mm256_zextsi128_si256");

	return disallowed_intrinsics;
}

fn parse_etype_from_str(e_type_name : &str) -> X86SIMDEType {
	match e_type_name {
		"UI8"  => X86SIMDEType::UInt8,
		"SI8"  => X86SIMDEType::Int8,
		"UI16" => X86SIMDEType::UInt16,
		"SI16" => X86SIMDEType::Int16,
		"UI32" => X86SIMDEType::UInt32,
		"SI32" => X86SIMDEType::Int32,
		"UI64" => X86SIMDEType::UInt64,
		"SI64" => X86SIMDEType::Int64,
		"FP32" => X86SIMDEType::Float32,
		"FP64" => X86SIMDEType::Float64,
		"M64"  => X86SIMDEType::M64,
		"M128" => X86SIMDEType::M128,
		"M256" => X86SIMDEType::M256,
		"MASK" => X86SIMDEType::Mask,
		_ => panic!("Bad etype '{}' in parse_etype_from_str", e_type_name)
	}
}

fn parse_type_from_str_no_imm(type_name : &str, e_type_name : Option<&str>) -> X86SIMDType {
	let type_name = type_name.trim_start_matches("const ");
	
	if type_name.starts_with("unsigned") {
		match type_name.trim_start_matches("unsigned ") {
			"char"      => X86SIMDType::Primitive(X86BaseType::UInt8),
			"short"     => X86SIMDType::Primitive(X86BaseType::UInt16),
			"int"       => X86SIMDType::Primitive(X86BaseType::UInt32),
			"__int64"   => X86SIMDType::Primitive(X86BaseType::UInt64),
			_ => panic!("Bad type name '{}' in parse_type_from_str", type_name)
		}
	}
	else {
		match type_name {
			"void"      => X86SIMDType::Primitive(X86BaseType::Void),
			"char"      => X86SIMDType::Primitive(X86BaseType::Int8),
			"__int8"    => X86SIMDType::Primitive(X86BaseType::Int8),
			"short"     => X86SIMDType::Primitive(X86BaseType::Int16),
			"__int16"   => X86SIMDType::Primitive(X86BaseType::Int16),
			"int"       => X86SIMDType::Primitive(X86BaseType::Int32),
			"__int32"   => X86SIMDType::Primitive(X86BaseType::Int32),
			"__int64"   => X86SIMDType::Primitive(X86BaseType::Int64),
			"long long" => X86SIMDType::Primitive(X86BaseType::Int64),
			"float"     => X86SIMDType::Primitive(X86BaseType::Float32),
			"double"    => X86SIMDType::Primitive(X86BaseType::Float64),
			"__m64"     => X86SIMDType::M64  (parse_etype_from_str(e_type_name.unwrap())),
			"__m128"    => X86SIMDType::M128 (parse_etype_from_str(e_type_name.unwrap())),
			"__m128d"   => X86SIMDType::M128d(parse_etype_from_str(e_type_name.unwrap())),
			"__m128i"   => X86SIMDType::M128i(parse_etype_from_str(e_type_name.unwrap())),
			"__m256"    => X86SIMDType::M256 (parse_etype_from_str(e_type_name.unwrap())),
			"__m256d"   => X86SIMDType::M256d(parse_etype_from_str(e_type_name.unwrap())),
			"__m256i"   => X86SIMDType::M256i(parse_etype_from_str(e_type_name.unwrap())),
			_ => panic!("Bad type name '{}' in parse_type_from_str", type_name)
		}
	}
}

// TODO: _mm_round_ps has IMM param, but doesn't specify width
fn parse_type_from_str(type_name : &str, e_type_name : Option<&str>, imm_width_input : Option<&str>) -> X86SIMDType {
	let parsed_type = parse_type_from_str_no_imm(type_name, e_type_name);
	if let Some(imm_width_str) = imm_width_input {
		if let X86SIMDType::Primitive(base_type) = parsed_type {
			return X86SIMDType::ConstantImmediate(base_type, imm_width_str.parse::<i32>().unwrap());
		}
		else {
			panic!("immwidth specified for non-primitive type");
		}
	}
	
	return parsed_type;
}

fn get_valid_cpuids() -> BTreeSet<&'static str> {
	let mut cpuids = BTreeSet::<&'static str>::new();
	for cpuid in ["AVX", "AVX2", "FMA", "SSE", "SSE2", "SSE3", "SSSE3" /*This is not a typo...at least not by me*/, "SSE4.1", "SSE4.2"].iter() {
		cpuids.insert(cpuid);
	}

	return cpuids;
}


pub fn parse_intel_intrinsics_xml(contents : &str) -> Vec::<X86SIMDIntrinsic> {
	let valid_cpuids = get_valid_cpuids();

	let disallowed_intrinsics = get_disallowed_intrinsics();

	let mut intrinsics_list = Vec::<X86SIMDIntrinsic>::with_capacity(256);

	let doc = roxmltree::Document::parse(&contents).unwrap();
	let root = doc.root_element();
	for child in root.children() {
		if child.has_tag_name("intrinsic") {
			let intrinsic_name = child.attribute("name").unwrap();
			
			// TODO: It'd be good to include these, but Clang on Windows doesn't support these
			// They aren't single-instruction intrinsics, they're like wrappers of sorts
			// And yeah, there's probably a way to coax Clang into doing it
			// Look me in the eyes
			// I do not care
			if let Some(is_sequence) = child.attribute("sequence") {
				if is_sequence == "TRUE" {
					continue;
				}
			}
			
			let mut cpuid : Option<&str> = None;
			let mut return_type : (Option<&str>, Option<&str>) = (None, None);
			let mut parameter_types = Vec::<(&str, Option<&str>, Option<&str>)>::with_capacity(4);

			for grandchild in child.children() {
				if grandchild.has_tag_name("CPUID") {
					cpuid = Some(grandchild.text().unwrap());
				}
				else if grandchild.has_tag_name("return") {
					return_type.0 = Some(grandchild.attribute("type").unwrap());
					return_type.1 = grandchild.attribute("etype");
				}
				else if grandchild.has_tag_name("parameter") {
					parameter_types.push( (grandchild.attribute("type").unwrap(), grandchild.attribute("etype"), grandchild.attribute("immwidth")) );
				}
			}

			let do_not_allow_intrinsic = disallowed_intrinsics.contains(intrinsic_name);

			if !do_not_allow_intrinsic {
				if let Some(cpuid) = cpuid {
					let (return_type,return_etype) = (return_type.0.unwrap(), return_type.1);
					
					let has_pointer_types = {
						let mut has_pointer_types = return_type.contains("*");
						for (parameter_type,_,_) in parameter_types.iter() {
							has_pointer_types |= parameter_type.contains("*");
						}
						has_pointer_types
					};

					if valid_cpuids.contains(&cpuid) && !has_pointer_types {
						let mut param_types = Vec::<X86SIMDType>::with_capacity(4);
						for (parameter_type,parameter_etype, param_imm_size) in parameter_types {
							let param_type = parse_type_from_str(parameter_type, parameter_etype, param_imm_size);
							
							//if matches!(param_type, X86SIMDType::M128i(X86SIMDEType::M256)) {
							//	panic!("bad intrinsic {}\n", intrinsic_name);
							//}
							
							if param_type != X86SIMDType::Primitive(X86BaseType::Void) {
								param_types.push(param_type);
							}
						}
						
						let return_type = parse_type_from_str(return_type, return_etype, None);
						
						let mut has_m64_type = matches!(return_type, X86SIMDType::M64(_));
						for param_type in param_types.iter() {
							has_m64_type |= matches!(param_type, X86SIMDType::M64(_));
						}
						
						let mut has_float_type = is_simd_type_floating_point(return_type);
						for param_type in param_types.iter() {
							has_float_type |= is_simd_type_floating_point(*param_type);
						}
						
						
						if !has_m64_type && !(MITIGATION_AVOID_FLOATING_POINT_INTRINSICS && has_float_type) {
							if ADJUST_ALIGNR_MASK_ARG && intrinsic_name == "_mm256_alignr_epi8" {
								param_types[2] = X86SIMDType::ConstantImmediate(X86BaseType::Int32, 4);
							}
							
							let intrinsic = X86SIMDIntrinsic {
								intrinsic_name: intrinsic_name.to_string(),
								return_type: return_type,
								param_types: param_types
							};

							intrinsics_list.push(intrinsic);
						}
					}
				}
			}
		}
	}
	
	return intrinsics_list;
}