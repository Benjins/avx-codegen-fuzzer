

// https://developer.arm.com/architectures/instruction-sets/intrinsics/data/intrinsics.json


use crate::arm_intrinsics::*;

use std::collections::BTreeSet;


// Floating point is for now too much of a headache to fuzz the way we do, unless we're doing crash-only
const MITIGATION_AVOID_FLOATING_POINT : bool = true;

// I don't know if these are supported everywhere?
const MITIGATION_AVOID_POLY128 : bool = true;
const MITIGATION_AVOID_POLY64 : bool = true;
const MITIGATION_AVOID_POLY32 : bool = true;

// Even if we allow floating point, float16 may not be supported
const MITIGATION_AVOID_FP16 : bool = true;

// An issue with NVCAST not having all type combinations specified,
// fixed in 830c18047bf8ce6d4d85345567847d344f97e975
const MITIGATION_AVOID_REINTERPRET : bool = false;

// I'd like to figure out if we can compile/run with these as well, but for now nix them
const MITIGATION_AVOID_A64_ONLY : bool = true;

const MITIGATION_AVOID_A64_ONLY_CVT_FLOAT : bool = true;


pub fn ignore_type_name_if(type_name : &str) -> bool {
	return type_name.contains("bfloat");
}

fn get_int_from_json(val : &serde_json::Value) -> i32 {
	if let Some(int_val) = val.as_i64() {
		return int_val as i32;
	}
	else if let Some(int_str_val) = val.as_str() {
		return int_str_val.parse::<i32>().unwrap();
	}
	else {
		println!("Couldn't parse {:?}", val);
		panic!("Could not parse int from json value");
	}
}

fn get_disallowed_intrinsics() -> BTreeSet<&'static str> {
	let mut disallowed_intrinsics = BTreeSet::<&'static str>::new();
	
	// unclear why this isn't found, idk
	disallowed_intrinsics.insert("__crc32b");
	disallowed_intrinsics.insert("__crc32h");
	disallowed_intrinsics.insert("__crc32w");
	disallowed_intrinsics.insert("__crc32d");
	disallowed_intrinsics.insert("__crc32cb");
	disallowed_intrinsics.insert("__crc32ch");
	disallowed_intrinsics.insert("__crc32cw");
	disallowed_intrinsics.insert("__crc32cd");

	// I guess AES stuff isn't supported either?
	disallowed_intrinsics.insert("vaesdq_u8");
	disallowed_intrinsics.insert("vaesmcq_u8");
	disallowed_intrinsics.insert("vaeseq_u8");
	disallowed_intrinsics.insert("vaesimcq_u8");

	// Nor dot products?
	disallowed_intrinsics.insert("vdot_s32");
	disallowed_intrinsics.insert("vdot_u32");
	disallowed_intrinsics.insert("vdotq_s32");
	disallowed_intrinsics.insert("vdotq_u32");
	disallowed_intrinsics.insert("vdot_lane_s32");
	disallowed_intrinsics.insert("vdot_lane_u32");
	disallowed_intrinsics.insert("vsudot_lane_s32");
	disallowed_intrinsics.insert("vsudot_lane_u32");
	disallowed_intrinsics.insert("vusdot_s32");
	disallowed_intrinsics.insert("vusdot_u32");
	disallowed_intrinsics.insert("vusdot_lane_s32");
	disallowed_intrinsics.insert("vusdot_lane_u32");
	disallowed_intrinsics.insert("vdotq_lane_s32");
	disallowed_intrinsics.insert("vdotq_lane_u32");
	disallowed_intrinsics.insert("vsudotq_lane_s32");
	disallowed_intrinsics.insert("vsudotq_lane_u32");
	disallowed_intrinsics.insert("vusdotq_lane_s32");
	disallowed_intrinsics.insert("vusdotq_lane_u32");
	disallowed_intrinsics.insert("vdotq_laneq_u32");
	disallowed_intrinsics.insert("vdotq_laneq_s32");
	disallowed_intrinsics.insert("vdot_laneq_s32");
	disallowed_intrinsics.insert("vdot_laneq_u32");

	// SHA-1 stuff...seriously of all the SHA's they chose SHA-1 to accelerate?
	disallowed_intrinsics.insert("vsha1cq_u32");
	disallowed_intrinsics.insert("vsha1pq_u32");
	disallowed_intrinsics.insert("vsha1mq_u32");
	disallowed_intrinsics.insert("vsha1h_u32");
	disallowed_intrinsics.insert("vsha1su0q_u32");
	disallowed_intrinsics.insert("vsha1su1q_u32");

	// Oh I guess they also accelerated SHA-256, nvm
	disallowed_intrinsics.insert("vsha256hq_u32");
	disallowed_intrinsics.insert("vsha256h2q_u32");
	disallowed_intrinsics.insert("vsha256su0q_u32");
	disallowed_intrinsics.insert("vsha256su1q_u32");

	// Matrix stuff?
	disallowed_intrinsics.insert("vmmlaq_s32");
	disallowed_intrinsics.insert("vmmlaq_u32");
	disallowed_intrinsics.insert("vusmmlaq_s32");
	disallowed_intrinsics.insert("vusmmlaq_u32");

	// rounding?
	disallowed_intrinsics.insert("vrnd64z_f32");
	disallowed_intrinsics.insert("vrnd64zq_f32");
	disallowed_intrinsics.insert("vrnd64z_f64");
	disallowed_intrinsics.insert("vrnd64zq_f64");
	disallowed_intrinsics.insert("vrnd64x_f32");
	disallowed_intrinsics.insert("vrnd64xq_f32");
	disallowed_intrinsics.insert("vrnd64x_f64");
	disallowed_intrinsics.insert("vrnd64xq_f64");

	disallowed_intrinsics.insert("vrnd32z_f32");
	disallowed_intrinsics.insert("vrnd32zq_f32");
	disallowed_intrinsics.insert("vrnd32z_f64");
	disallowed_intrinsics.insert("vrnd32zq_f64");
	disallowed_intrinsics.insert("vrnd32x_f32");
	disallowed_intrinsics.insert("vrnd32xq_f32");
	disallowed_intrinsics.insert("vrnd32x_f64");
	disallowed_intrinsics.insert("vrnd32xq_f64");

	return disallowed_intrinsics;
}

pub fn parse_arm_intrinsics_json(spec_contents : &str) -> Vec<ARMSIMDIntrinsic> {
	let spec_json : serde_json::Value = serde_json::from_str(spec_contents).expect("Could not parse JSON");
	
	let disallowed_intrinsics = get_disallowed_intrinsics();
	
	let mut intrinsics_list = Vec::new();
	
	for intrinsic_json in spec_json.as_array().expect("ARM spec should be a single global JSON array") {
		if intrinsic_json["SIMD_ISA"].as_str().expect("") == "Neon" {
			
			let mut a64_only = true;
			for arch in intrinsic_json["Architectures"].as_array().expect("") {
				if arch != "A64" {
					a64_only = false;
					break;
				}
			}
			
			let a64_only = a64_only;
			
			if MITIGATION_AVOID_A64_ONLY {
				if a64_only {
					continue;
				}
			}
			
			let name = intrinsic_json["name"].as_str().expect("");
			
			if disallowed_intrinsics.contains(name) {
				continue;
			}
			
			if MITIGATION_AVOID_A64_ONLY_CVT_FLOAT {
				if name.starts_with("vcvt") && a64_only {
					continue;
				}
			}
			
			if MITIGATION_AVOID_REINTERPRET {
				if name.contains("reinterpret") {
					continue;
				}
			}
			
			let return_type = intrinsic_json["return_type"]["value"].as_str().expect("");
			let mut args = Vec::new();
			for arg in intrinsic_json["arguments"].as_array().expect("") {
				args.push(arg.as_str().expect(""));
			}

			if ignore_type_name_if(return_type) || args.iter().any(|&arg| ignore_type_name_if(arg)) { continue; }
			
			if args.iter().any(|&arg| arg.contains("*") && !arg.contains("const")) {
				// Store instructions, or other intrinsics that write to memory
				continue;
			}
			else if args.iter().any(|&arg| arg.contains("*")) {
				// load instructions: for now also skip these, since we kinda just hack them in later
				// could maybe do something more interesting
				continue;
			}

			let mut intrinsic_args = Vec::new();
			let ret_type = parse_arm_simd_type(return_type);
			for arg in args {
				if let Some(arg_name) = arg.strip_prefix("const int ") {
					
					let arg_prep = &intrinsic_json["Arguments_Preparation"][arg_name];
					let min = get_int_from_json(&arg_prep["minimum"]);
					let max = get_int_from_json(&arg_prep["maximum"]);
					intrinsic_args.push(ARMSIMDType::ConstantIntImmediate(min, max));
				}
				else {
					let arg_type_name = arg.split_ascii_whitespace().next().unwrap();
					let arg_type = parse_arm_simd_type(arg_type_name);
					intrinsic_args.push(arg_type);
				}
			}

			if MITIGATION_AVOID_FLOATING_POINT {
				if is_arm_simd_type_floating_point(ret_type) || intrinsic_args.iter().any(|&arg| is_arm_simd_type_floating_point(arg)) {
					continue;
				}
			}
			
			if MITIGATION_AVOID_POLY128 {
				if is_arm_simd_type_base_type(ret_type, ARMBaseType::Poly128)
				|| intrinsic_args.iter().any(|&arg| is_arm_simd_type_base_type(arg, ARMBaseType::Poly128)) {
					continue;
				}
			}
			
			if MITIGATION_AVOID_POLY64 {
				if is_arm_simd_type_base_type(ret_type, ARMBaseType::Poly64)
				|| intrinsic_args.iter().any(|&arg| is_arm_simd_type_base_type(arg, ARMBaseType::Poly64)) {
					continue;
				}
			}
			
			if MITIGATION_AVOID_POLY32 {
				if is_arm_simd_type_base_type(ret_type, ARMBaseType::Poly32)
				|| intrinsic_args.iter().any(|&arg| is_arm_simd_type_base_type(arg, ARMBaseType::Poly32)) {
					continue;
				}
			}
			
			if MITIGATION_AVOID_FP16 {
				if is_arm_simd_type_base_type(ret_type, ARMBaseType::Float16)
				|| intrinsic_args.iter().any(|&arg| is_arm_simd_type_base_type(arg, ARMBaseType::Float16)) {
					continue;
				}
			}
			

			let intrinsic = ARMSIMDIntrinsic{intrinsic_name: name.to_string(), return_type: ret_type, param_types: intrinsic_args};
			//println!("intrinsic {:?}", intrinsic);
			
			intrinsics_list.push(intrinsic);
		}
	}
	
	return intrinsics_list;
}

