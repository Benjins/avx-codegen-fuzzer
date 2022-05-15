

use crate::arm_intrinsics::*;

use std::collections::HashMap;

use std::fmt::Write;

use crate::codegen_fuzzing::CodegenFuzzer;
use crate::rand::Rand;

use crate::arm_codegen_ctx::ARMSIMDCodegenCtx;
use crate::arm_codegen_ctx::{generate_arm_codegen_ctx, generate_cpp_code_from_arm_codegen_ctx};

use crate::exec_mem::ExecPage;

use crate::code_exe_server_conn::{CodeExeAndInput, CodeExeServClient};


// 192.168.86.153 for exe server


pub struct ARMCodegenFuzzerCodeMetadata {
	num_i_vals : usize,
	num_f_vals : usize,
	num_d_vals : usize,
	return_type : ARMSIMDType
}

pub struct ARMCodegenFuzzerThreadInput {
	pub thread_seed : u64,
	pub type_to_intrinsics_map : HashMap<ARMSIMDType, Vec<ARMSIMDIntrinsic>>
}

pub struct ARMCodegenFuzzer {
	type_to_intrinsics_map : HashMap<ARMSIMDType, Vec<ARMSIMDIntrinsic>>,
	all_intrinsic_return_types : Vec<ARMSIMDType>,
	outer_rng : Rand,
	code_exe_serv : CodeExeServClient
}

#[derive(Clone, Debug)]
pub struct ARMCodeFuzzerInputValues {
	pub i_vals : Vec<i32>,
	pub f_vals : Vec<f32>,
	pub d_vals : Vec<f64>
}

impl ARMCodeFuzzerInputValues {
	pub fn write_to_str(&self) -> String {
		let mut out_str = String::with_capacity(4096);

		write!(out_str, "{}\n", self.i_vals.len()).expect("");
		for i_val in self.i_vals.iter() {
			write!(out_str, "{} ", i_val).expect("");
		}
		
		write!(out_str, "{}\n", self.f_vals.len()).expect("");
		for f_val in self.f_vals.iter() {
			write!(out_str, "{} ", f_val).expect("");
		}
		
		write!(out_str, "{}\n", self.d_vals.len()).expect("");
		for d_val in self.d_vals.iter() {
			write!(out_str, "{} ", d_val).expect("");
		}
		
		return out_str;
	}
}

#[derive(Copy, Clone, Debug)]
pub struct ARMSIMDOutputValues {
	pub output_bytes : [u8; 64],
	pub output_len : usize
}


fn minimize_gen_arm_code<F: Fn(&ARMCodegenFuzzer, &ARMSIMDCodegenCtx) -> bool>(fuzzer: &ARMCodegenFuzzer, codegen_ctx : &ARMSIMDCodegenCtx, minim_check: F) -> ARMSIMDCodegenCtx {
	let mut best_ctx = codegen_ctx.clone();

	loop {
		let mut made_progress = false;

		// For each node, try to replace it with a no-op,
		// and change all downstream references to something else
		for ii in 1..best_ctx.get_num_nodes() {
			if let Some(intrinsic_node) = best_ctx.maybe_get_produced_node(ii) {
				print!("Trying to remove node {} {:?}\n", ii, intrinsic_node);
				let mut new_ctx = best_ctx.clone();
				let return_type = intrinsic_node.intrinsic.return_type;
				let mut can_replace_downstream_refs = true;
				
				//print!("Current type_to_ref_idx is {:?}\n", new_ctx.type_to_ref_idx);
				
				// For each node before the one we're trying to remove
				for jj in 0..ii {
					if let Some(ref mut downstream_node) = new_ctx.maybe_get_produced_node_mut(jj) {
						// If it references the node we're trying to remove
						for ref_idx in downstream_node.references.iter_mut() {
							if *ref_idx == ii {
								// Check if we can replace that reference with something else
								if let Some(new_idx) = best_ctx.maybe_get_node_of_type(return_type, jj, ii) {
									*ref_idx = new_idx;
								}
								else {
									// If not, bail
									can_replace_downstream_refs = false;
									break;
								}
							}
						}
						
						if can_replace_downstream_refs {
							for ref_idx in downstream_node.references.iter_mut() {
								assert!(*ref_idx != ii);
							}
						}
						
						if !can_replace_downstream_refs{
							break;
						}
					}
				}
				
				// If we successfully replaced all downstream refs
				if can_replace_downstream_refs {
					new_ctx.mark_node_as_noop(ii);
					print!("Trying to remove node {}, seeing if issue still repros...\n", ii);
					if minim_check(fuzzer, &new_ctx) {
						print!("Issue still repros, so we've made progress!\n");
						made_progress = true;
						best_ctx = new_ctx;
						break;
					}
				}
			}
		}
		
		if !made_progress {
			print!("Could no longer make progress on any current nodes\n");
			break;
		}
	}

	return best_ctx.clone();
}

fn generate_random_input_for_program(num_i_vals : usize, num_f_vals : usize, num_d_vals : usize) -> ARMCodeFuzzerInputValues {
	let mut rng = Rand::default();

	let mut i_vals = Vec::<i32>::with_capacity(num_i_vals);
	for _ in 0..num_i_vals {
		let rand_val = match (rng.rand() % 16) {
			0 =>  0,
			1 =>  1,
			2 =>  2,
			3 => -1,
			_ => rng.rand() as i32
		};
		i_vals.push(rand_val);
	}
	
	let mut f_vals = Vec::<f32>::with_capacity(num_f_vals);
	for _ in 0..num_f_vals { f_vals.push(rng.randf() * 2.0 - 1.0); }
	
	let mut d_vals = Vec::<f64>::with_capacity(num_d_vals);
	for _ in 0..num_d_vals { d_vals.push((rng.randf() * 2.0 - 1.0) as f64); }

	return ARMCodeFuzzerInputValues { i_vals: i_vals, f_vals: f_vals, d_vals: d_vals };
}

fn base_type_to_core_type_and_ln2_bits(base_type : ARMBaseType) -> (u32, u32) {
	match base_type {
		ARMBaseType::Void => panic!("cannot call base_type_to_core_type_and_ln2_bits on void"),
		ARMBaseType::Int8 => (0, 3),
		ARMBaseType::UInt8 => (1, 3),
		ARMBaseType::Int16 => (0, 4),
		ARMBaseType::UInt16 => (1, 4),
		ARMBaseType::Int32 => (0, 5),
		ARMBaseType::UInt32 => (1, 5),
		ARMBaseType::Int64 => (0, 6),
		ARMBaseType::UInt64 => (1, 6),
		ARMBaseType::Float16 => (2, 4),
		ARMBaseType::Float32 => (2, 5),
		ARMBaseType::Float64 => (2, 6),
		ARMBaseType::Poly8 => (3, 3),
		ARMBaseType::Poly16 => (3, 4),
		ARMBaseType::Poly32 => (3, 5),
		ARMBaseType::Poly64 => (3, 6),
		ARMBaseType::Poly128 => (3, 7)
	}
}

// is there a log2? I don't know, and it is far too late at night for me to care
// ALSO: +1 to the log2 so we can use 0 to show that it's a primitive...idk y;all
fn encode_simd_count(count : u32) -> u32 {
	match count {
		1 => 1,
		2 => 2,
		4 => 3,
		8 => 4,
		16 => 5,
		_ => panic!("bad simd count encoded {}", count)
	}
}

fn encode_return_type(return_type : ARMSIMDType) -> u32 {
	match return_type {
		ARMSIMDType::Primitive(base_type) => {
			let (core_type, ln2_bits) = base_type_to_core_type_and_ln2_bits(base_type);
			return core_type | (ln2_bits << 2);
		}
		ARMSIMDType::SIMD(base_type, count) => {
			let (core_type, ln2_bits) = base_type_to_core_type_and_ln2_bits(base_type);
			return core_type | (ln2_bits << 2) | (encode_simd_count(count as u32) << 5);
		}
		ARMSIMDType::SIMDArr(base_type, count, array_len) => {
			let (core_type, ln2_bits) = base_type_to_core_type_and_ln2_bits(base_type);
			return core_type | (ln2_bits << 2) | (encode_simd_count(count as u32) << 5) | (((array_len - 1) as u32) << 8);
		}
		_ => { panic!("bad return type {:?}", return_type); }
	}
}

impl CodegenFuzzer<ARMCodegenFuzzerThreadInput, ARMSIMDCodegenCtx, ARMCodegenFuzzerCodeMetadata, ARMCodeFuzzerInputValues, ARMSIMDOutputValues> for ARMCodegenFuzzer {
	// Each of these will go on a thread, can contain inputs like
	// a parsed spec data, seed, flags, config, etc.
	fn new_fuzzer_state(input_data : Self::ThreadInput) -> Self {
		let mut all_intrinsic_return_types = Vec::new();
		for (ret_type, _) in input_data.type_to_intrinsics_map.iter() {
			all_intrinsic_return_types.push(*ret_type);
		}

		const EXE_SERVER_ADDR_AND_PORT : &str = "192.168.86.153:6821";

		ARMCodegenFuzzer {
			type_to_intrinsics_map: input_data.type_to_intrinsics_map,
			all_intrinsic_return_types: all_intrinsic_return_types,
			outer_rng: Rand::new(input_data.thread_seed),
			code_exe_serv: CodeExeServClient::new(EXE_SERVER_ADDR_AND_PORT)
		}
	}

	// This generates some context struct that's basically analagous to the AST
	fn generate_ctx(&mut self) -> Self::CodegenCtx {
		let mut codegen_ctx = Self::CodegenCtx::new(self.outer_rng.rand_u64());
		generate_arm_codegen_ctx(&mut codegen_ctx, &self.type_to_intrinsics_map, &self.all_intrinsic_return_types);
		return codegen_ctx;
	}

	// Turn the AST/context into actual CPP code, along with any metadata (i.e. number of values to pass for SIMD's iVals pointer, return value, etc.)
	fn generate_cpp_code(&self, ctx : &Self::CodegenCtx) -> (String, Self::CodeMeta) {
		let (cpp_code, num_i_vals, num_f_vals, num_d_vals) = generate_cpp_code_from_arm_codegen_ctx(&ctx);
		let meta_data = Self::CodeMeta {
			num_i_vals: num_i_vals,
			num_f_vals: num_f_vals,
			num_d_vals: num_d_vals,
			return_type: ctx.get_return_type()
		};
		return (cpp_code, meta_data);
	}

	fn generate_random_input(&self, code_meta : &Self::CodeMeta) -> Self::FuzzerInput {
		return generate_random_input_for_program(code_meta.num_i_vals, code_meta.num_f_vals, code_meta.num_d_vals);
	}

	// uhh.....idk
	fn try_minimize<F: Fn(&Self, &Self::CodegenCtx) -> bool>(&self, ctx: Self::CodegenCtx, func: F) -> Option<Self::CodegenCtx> {
		Some(minimize_gen_arm_code(self, &ctx, func))
	}

	// Actually execute it: this is probably like local, but 
	fn execute(&self, exec_page : &ExecPage, code_meta: &Self::CodeMeta, input : &Self::FuzzerInput) -> Self::FuzzerOutput {
		
		let encoded_return_type = encode_return_type(code_meta.return_type);
		println!("{:?} return type encoded as {}", code_meta.return_type, encoded_return_type);

		let code_exe_and_input = CodeExeAndInput {
			code_bytes: exec_page.get_bytes(),
			func_offset: exec_page.get_func_offset() as u32,
			i_vals: &input.i_vals[..],
			f_vals: &input.f_vals[..],
			d_vals: &input.d_vals[..],
			return_type : encoded_return_type
		};

		let maybe_output = self.code_exe_serv.send_exe_and_input(&code_exe_and_input);
		match maybe_output {
			Ok(output_vec) => {
				
				assert!(output_vec.len() <= 64);
				
				let mut output_bytes = [0u8 ; 64];
				
				for (ii, val) in output_vec.iter().enumerate() {
					output_bytes[ii] = *val;
				}
				
				let actual_out = ARMSIMDOutputValues{ output_bytes: output_bytes, output_len: output_vec.len() };
				println!("woo hoo, we got an actual output {:?}", actual_out);
				return actual_out;
			}
			Err(err) => {
				panic!("Oh no, we got an IO error {}", err);
			}
		}
		
	}

	fn are_outputs_the_same(&self, o1 : &Self::FuzzerOutput, o2 : &Self::FuzzerOutput) -> bool {
		if o1.output_len == o2.output_len {
			return &o1.output_bytes[..o1.output_len] == &o2.output_bytes[..o2.output_len];
		}
		else {
			return false;
		}
	}
	
	fn save_input_to_string(&self, input : &Self::FuzzerInput) -> String {
		return input.write_to_str();
	}
	
	fn num_inputs_per_codegen(&self) -> u32 {
		1
	}
}



