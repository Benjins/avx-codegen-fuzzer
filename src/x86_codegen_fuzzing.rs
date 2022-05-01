
use std::collections::HashMap;
use std::convert::TryInto;

use std::fmt::Write;

use crate::codegen_fuzzing::CodegenFuzzer;
use crate::rand::Rand;

use crate::x86_codegen_ctx::X86SIMDCodegenCtx;
use crate::x86_codegen_ctx::{generate_cpp_code_from_x86_codegen_ctx, generate_x86_codegen_ctx};

// kinda just need all of this lol
use crate::x86_intrinsics::*;

use crate::exec_mem::ExecPage;

pub struct X86CodegenFuzzerCodeMetadata {
	num_i_vals : usize,
	num_f_vals : usize,
	num_d_vals : usize,
	return_type : X86SIMDType
}

pub struct X86CodegenFuzzerThreadInput {
	pub thread_seed : u64,
	pub type_to_intrinsics_map : HashMap<X86SIMDType, Vec<X86SIMDIntrinsic>>
}

pub struct X86CodegenFuzzer {
	type_to_intrinsics_map : HashMap<X86SIMDType, Vec<X86SIMDIntrinsic>>,
	outer_rng : Rand,
}

#[derive(Clone, Debug)]
pub struct X86CodeFuzzerInputValues {
	pub i_vals : Vec<i32>,
	pub f_vals : Vec<f32>,
	pub d_vals : Vec<f64>
}

impl X86CodeFuzzerInputValues {
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
pub enum X86SIMDOutputValues {
	SIMD128Bit(std::simd::u8x16),
	SIMD256Bit(std::simd::u8x32)
}

fn generate_random_input_for_program(num_i_vals : usize, num_f_vals : usize, num_d_vals : usize) -> X86CodeFuzzerInputValues {
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

	return X86CodeFuzzerInputValues { i_vals: i_vals, f_vals: f_vals, d_vals: d_vals };
}

fn minimize_gen_code<F: Fn(&X86CodegenFuzzer, &X86SIMDCodegenCtx) -> bool>(fuzzer: &X86CodegenFuzzer, codegen_ctx : &X86SIMDCodegenCtx, minim_check: F) -> X86SIMDCodegenCtx {
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
					//print!("Checking downstream node {}\n", jj);
					if let Some(ref mut downstream_node) = new_ctx.maybe_get_produced_node_mut(jj) {
						//print!("Downstream node {} is produced ({:?} refs)\n", jj, downstream_node.references);
						// If it references the node we're trying to remove
						for ref_idx in downstream_node.references.iter_mut() {
							if *ref_idx == ii {
								// Check if we can replace that reference with something else
								if let Some(new_idx) = best_ctx.maybe_get_node_of_type(return_type, jj, ii) {
									//print!("Swap node {} for {}\n", *ref_idx, new_idx);
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

impl CodegenFuzzer<X86CodegenFuzzerThreadInput, X86SIMDCodegenCtx, X86CodegenFuzzerCodeMetadata, X86CodeFuzzerInputValues, X86SIMDOutputValues> for X86CodegenFuzzer {
	// Each of these will go on a thread, can contain inputs like
	// a parsed spec data, seed, flags, config, etc.
	fn new_fuzzer_state(input_data : Self::ThreadInput) -> X86CodegenFuzzer {
		X86CodegenFuzzer {
			type_to_intrinsics_map: input_data.type_to_intrinsics_map,
			outer_rng: Rand::new(input_data.thread_seed)
		}
	}

	// This generates some context struct that's basically analagous to the AST
	fn generate_ctx(&mut self) -> Self::CodegenCtx {
		let mut codegen_ctx = Self::CodegenCtx::new(self.outer_rng.rand_u64());
		generate_x86_codegen_ctx(&mut codegen_ctx, &self.type_to_intrinsics_map);
		return codegen_ctx;
	}

	// Turn the AST/context into actual CPP code, along with any metadata (i.e. number of values to pass for SIMD's iVals pointer, return value, etc.)
	fn generate_cpp_code(&self, ctx : &Self::CodegenCtx) -> (String, Self::CodeMeta) {
		let (cpp_code, num_i_vals, num_f_vals, num_d_vals) = generate_cpp_code_from_x86_codegen_ctx(&ctx);
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
		Some(minimize_gen_code(self, &ctx, func))
	}

	// Actually execute it: this is probably like local, but 
	fn execute(&self, exec_page : &ExecPage, code_meta: &Self::CodeMeta, input : &Self::FuzzerInput) -> Self::FuzzerOutput {
		match code_meta.return_type {
			X86SIMDType::M256i(_) => {
				let ret = exec_page.execute_with_args_256i(&input.i_vals[..], &input.f_vals[..], &input.d_vals[..]);
				let bytes_256 : std::simd::u8x32 = ret.try_into().unwrap();
				return Self::FuzzerOutput::SIMD256Bit(bytes_256);
			},
			X86SIMDType::M128i(_) => {
				let ret = exec_page.execute_with_args_128i(&input.i_vals[..], &input.f_vals[..], &input.d_vals[..]);
				let bytes_128 : std::simd::u8x16 = ret.try_into().unwrap();
				return Self::FuzzerOutput::SIMD128Bit(bytes_128);
			},
			_ => { panic!("Bad return type for simd"); }
		}
	}

	fn are_outputs_the_same(&self, o1 : &Self::FuzzerOutput, o2 : &Self::FuzzerOutput) -> bool {
		match (o1, o2) {
			(Self::FuzzerOutput::SIMD128Bit(b1), Self::FuzzerOutput::SIMD128Bit(b2)) => {
				return b1 == b2;
			},
			(Self::FuzzerOutput::SIMD256Bit(b1), Self::FuzzerOutput::SIMD256Bit(b2)) => {
				return b1 == b2;
			},
			_ => { return false; }
		}
	}
	
	fn save_input_to_string(&self, input : &Self::FuzzerInput) -> String {
		input.write_to_str()
	}
}

