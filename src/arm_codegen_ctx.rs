
use std::collections::HashMap;

use std::fmt::Write;

use crate::arm_intrinsics::*;
use crate::rand::Rand;


#[derive(Debug, Clone)]
pub struct ARMSIMDCodegenIntrinsic {
	pub intrinsic : ARMSIMDIntrinsic,
	pub references : Vec<usize>
}

#[derive(Debug, Clone)]
pub enum ARMSIMDCodegenNode {
	Immediate(ARMBaseType, i64, f64),
	ConstantImmediate(i32),
	Entry(ARMSIMDType),
	Zero(ARMSIMDType),
	Produced(ARMSIMDCodegenIntrinsic),
	Pending(ARMSIMDType),
	NoOp // Used for minimization
}


#[derive(Default, Clone)]
pub struct ARMSIMDCodegenCtx {
	// 0 is the last, and it goes backward chronologically
	pub intrinsics_sequence : Vec<ARMSIMDCodegenNode>,

	// For a given type, track all the node indices that produce that type
	pub type_to_ref_idx : HashMap<ARMSIMDType, Vec<usize>>,
	
	// Some RNG state
	rng : Rand
}


const REUSE_NODE_IDX_DENOM : u32 = 6;
const REUSE_NODE_IDX_NUM : u32 = 1;

impl ARMSIMDCodegenCtx {
	pub fn new(seed : u64) -> ARMSIMDCodegenCtx {
		ARMSIMDCodegenCtx {
			intrinsics_sequence: Vec::new(),
			type_to_ref_idx: HashMap::new(),
			rng: Rand::new(seed)
		}
	}
	
	pub fn get_ref_of_type(&mut self, ref_type : ARMSIMDType, before_idx : usize) -> usize {
		if let Some(ref_indices) = self.type_to_ref_idx.get(&ref_type) {
			for ref_idx in ref_indices {
				if *ref_idx > before_idx {
					if (self.rng.rand() % REUSE_NODE_IDX_DENOM) < REUSE_NODE_IDX_NUM {
						return *ref_idx;
					}
				}
			}
		}
		
		let new_ref_idx = self.intrinsics_sequence.len();
		if let ARMSIMDType::ConstantIntImmediate(min_val, max_val) = ref_type {
			let random_val = (self.rng.rand() % (max_val - min_val + 1) as u32) as i32 + min_val;
			self.intrinsics_sequence.push(ARMSIMDCodegenNode::ConstantImmediate(random_val));
		}
		else {
			self.intrinsics_sequence.push(ARMSIMDCodegenNode::Pending(ref_type));
		}

		let ref_indices: &mut Vec<usize> = self.type_to_ref_idx.entry(ref_type).or_insert_with(|| Vec::<usize>::with_capacity(4));
		ref_indices.push(new_ref_idx);
		
		return new_ref_idx;
	}
	
	pub fn maybe_get_node_of_type(&self, ref_type : ARMSIMDType, before_idx : usize, not_idx : usize) -> Option<usize> {
		if let Some(ref_indices) = self.type_to_ref_idx.get(&ref_type) {
			for ref_idx in ref_indices {
				if *ref_idx > before_idx && *ref_idx != not_idx {
					return Some(*ref_idx);
				}
			}
		}
		
		return None;
	}
	
	pub fn get_type_of_pending_node(&self, node_idx : usize) -> Option<ARMSIMDType> {
		match &self.intrinsics_sequence[node_idx] {
			ARMSIMDCodegenNode::Immediate(_,_,_) => None,
			ARMSIMDCodegenNode::Entry(_) => panic!("this shouldn't happen"),
			ARMSIMDCodegenNode::ConstantImmediate(_) => None,
			ARMSIMDCodegenNode::Produced(_) => None,
			ARMSIMDCodegenNode::Zero(_) => None,
			ARMSIMDCodegenNode::Pending(node_type) => Some(*node_type),
			ARMSIMDCodegenNode::NoOp => None
		}
	}
	
	pub fn get_num_nodes(&self) -> usize {
		return self.intrinsics_sequence.len();
	}
	
	pub fn _debug_print(&self) {
		for (idx, node) in self.intrinsics_sequence.iter().enumerate() {
			print!("ARM Node {:3} {:?}\n", idx, node);
		}
	}
	
	pub fn produce_for_idx(&mut self, idx : usize, node_intrinsic : ARMSIMDCodegenIntrinsic) {
		if let ARMSIMDCodegenNode::Pending(node_type) = self.intrinsics_sequence[idx] {
			assert!(node_type == node_intrinsic.intrinsic.return_type);
			self.intrinsics_sequence[idx] = ARMSIMDCodegenNode::Produced(node_intrinsic);
		}
		else {
			panic!("node at index {} has already been produced", idx);
		}
	}
	
	pub fn mark_node_as_entry(&mut self, node_idx : usize) {
		match self.intrinsics_sequence[node_idx] {
			ARMSIMDCodegenNode::Pending(node_type) => self.intrinsics_sequence[node_idx] = ARMSIMDCodegenNode::Entry(node_type),
			_ => panic!("this shouldn't happen")
		}
	}
	
	pub fn mark_node_as_immediate(&mut self, node_idx : usize, imm_type : ARMBaseType) {
		match self.intrinsics_sequence[node_idx] {
			// TODO: Pick actual numbers
			ARMSIMDCodegenNode::Pending(node_type) => {
				match node_type {
					ARMSIMDType::Primitive(base_type) => assert!(base_type == imm_type),
					_ => panic!("bad type in mark_node_as_immediate {:?}", node_type)
				}
				
				// TODO: why the zeros?
				self.intrinsics_sequence[node_idx] = ARMSIMDCodegenNode::Immediate(imm_type, 0, 0.0);
			}
			_ => panic!("this shouldn't happen")
		}
	}
	
	pub fn mark_node_as_zero(&mut self, node_idx : usize) {
		if let ARMSIMDCodegenNode::Pending(node_type) = self.intrinsics_sequence[node_idx] {
			self.intrinsics_sequence[node_idx] = ARMSIMDCodegenNode::Zero(node_type);
		}
		else {
			panic!("node at index {} has already been produced", node_idx);
		}
	}
	
	pub fn get_return_node_idx(&self) -> usize {
		return 0;
		//let mut return_node_idx = 0;
		//while return_node_idx < self.intrinsics_sequence.len() && matches!(self.intrinsics_sequence[return_node_idx], X86SIMDCodegenNode::OptBait(_)) {
		//	return_node_idx += 1;
		//}
		//
		//if return_node_idx >= self.intrinsics_sequence.len() {
		//	print!("Intrinsics sequence:\n{:?}\n", &self.intrinsics_sequence);
		//	panic!("bad codegen ctx: could not find return node");
		//}
		//
		//return return_node_idx;
	}
	
	pub fn get_return_type(&self) -> ARMSIMDType {
		let return_node_idx = self.get_return_node_idx();

		let return_type = if let ARMSIMDCodegenNode::Produced(node_intrinsic) = &self.intrinsics_sequence[return_node_idx] {
			node_intrinsic.intrinsic.return_type
		}
		else if let ARMSIMDCodegenNode::Entry(node_type) = &self.intrinsics_sequence[return_node_idx] {
			*node_type
		}
		else if let ARMSIMDCodegenNode::Zero(node_type) = &self.intrinsics_sequence[return_node_idx] {
			*node_type
		}
		else {
			print!("Return node:\n{:?}\n", &self.intrinsics_sequence[return_node_idx]);
			panic!("bad return node")
		};
		
		return return_type;
	}
}


pub fn generate_arm_codegen_ctx(ctx : &mut ARMSIMDCodegenCtx, intrinsics_by_type : &HashMap<ARMSIMDType, Vec<ARMSIMDIntrinsic>>, all_intrinsic_return_types : &Vec<ARMSIMDType>) {
	let ending_type = all_intrinsic_return_types[ctx.rng.rand_size() % all_intrinsic_return_types.len()];
	let _ = ctx.get_ref_of_type(ending_type, 0);

	let num_node_iterations : usize = 30;//40 + (ctx.rng.rand_size() % 100);
	let chance_for_zero_node : f32 = 0.0;//match (ctx.rng.rand() % 4) { 0 => 0.0001, 1 => 0.001, 2 => 0.01, 3 => 0.02, _ => panic!("") };

	for ii in 0..num_node_iterations {
		if ii >= ctx.get_num_nodes() {
			let _ = ctx.get_ref_of_type(ending_type, ii);
		}

		if let Some(node_type) = ctx.get_type_of_pending_node(ii) {
			if ii > 0 && ctx.rng.randf() < chance_for_zero_node {
				ctx.mark_node_as_zero(ii);
			}
			else {
				let intrinsics_for_type = intrinsics_by_type.get(&node_type);
				if let Some(intrinsics_for_type) = intrinsics_for_type {
					let intrinsic_to_use = &intrinsics_for_type[ctx.rng.rand_size() % intrinsics_for_type.len()];

					let mut node_intrinsic = ARMSIMDCodegenIntrinsic {
						intrinsic: intrinsic_to_use.clone(),
						references: Vec::<usize>::new()
					};
					
					for param_type in &intrinsic_to_use.param_types {
						let ref_idx = ctx.get_ref_of_type(*param_type, ii);
						node_intrinsic.references.push(ref_idx);
					}
					
					ctx.produce_for_idx(ii, node_intrinsic);
				}
				// The only cases where we can't produce a type via intrinsics should be primitive types like uint8
				else if let ARMSIMDType::Primitive(prim_type) = node_type {
					ctx.mark_node_as_immediate(ii, prim_type);
				}
				else {
					// Some types are only produced by load instructions, so those need to be entry nodes
					ctx.mark_node_as_entry(ii);
				}
			}
		}
	}

	for ii in num_node_iterations..ctx.get_num_nodes() {
		if ctx.get_type_of_pending_node(ii).is_some() {
			ctx.mark_node_as_entry(ii);
		}
	}
}

fn arm_generate_cpp_entry_code_for_type(cpp_code: &mut String, var_idx : usize, entry_type : ARMSIMDType, num_i_vals : usize, num_f_vals : usize, num_d_vals : usize) -> (usize, usize, usize) {
	write!(cpp_code, "\t{} var_{} = {{}};", arm_simd_type_to_cpp_type_name(entry_type), var_idx).expect("");

	const SIMD_ALIGNMENT_BYTES : usize = 16;
	
	return (num_i_vals, num_f_vals, num_d_vals);

	//match entry_type {
	//	X86SIMDType::Primitive(base_type) => {
	//		match base_type {
	//			X86BaseType::Int8 => {
	//				write!(cpp_code, "(char)(iVals[{}])", num_i_vals).expect("");
	//				return (num_i_vals + 1, num_f_vals, num_d_vals);
	//			}
	//			X86BaseType::UInt8 => {
	//				write!(cpp_code, "(unsigned char)(iVals[{}])", num_i_vals).expect("");
	//				return (num_i_vals + 1, num_f_vals, num_d_vals);
	//			}
	//			X86BaseType::Int16 => {
	//				write!(cpp_code, "(short)(iVals[{}])", num_i_vals).expect("");
	//				return (num_i_vals + 1, num_f_vals, num_d_vals);
	//			}
	//			X86BaseType::UInt16 => {
	//				write!(cpp_code, "(unsigned short)(iVals[{}])", num_i_vals).expect("");
	//				return (num_i_vals + 1, num_f_vals, num_d_vals);
	//			}
	//			X86BaseType::Int32 => {
	//				write!(cpp_code, "(int)(iVals[{}])", num_i_vals).expect("");
	//				return (num_i_vals + 1, num_f_vals, num_d_vals);
	//			}
	//			X86BaseType::UInt32 => {
	//				write!(cpp_code, "(unsigned int)(iVals[{}])", num_i_vals).expect("");
	//				return (num_i_vals + 1, num_f_vals, num_d_vals);
	//			}
	//			X86BaseType::Int64 => {
	//				write!(cpp_code, "(long long)(iVals[{}])", num_i_vals).expect("");
	//				return (num_i_vals + 1, num_f_vals, num_d_vals);
	//			}
	//			X86BaseType::UInt64 => {
	//				write!(cpp_code, "(unsigned long long)(iVals[{}])", num_i_vals).expect("");
	//				return (num_i_vals + 1, num_f_vals, num_d_vals);
	//			}
	//			X86BaseType::Float32 => {
	//				write!(cpp_code, "fVals[{}]", num_f_vals).expect("");
	//				return (num_i_vals, num_f_vals + 1, num_d_vals);
	//			}
	//			X86BaseType::Float64 => {
	//				write!(cpp_code, "dVals[{}]", num_d_vals).expect("");
	//				return (num_i_vals, num_f_vals, num_d_vals + 1);
	//			}
	//			_ => panic!("void or bad base type")
	//		}
	//	}
	//	X86SIMDType::ConstantImmediate(_, _) => { panic!("Immediate") }
	//	X86SIMDType::M64(_) => {
	//		// TODO: Don't broadcast?
	//		let start_idx = align_usize(num_i_vals, SIMD_ALIGNMENT_BYTES / 4);
	//		write!(cpp_code, "_mm_set1_pi32(iVals[{}])", start_idx).expect("");
	//		return (start_idx + 2, num_f_vals, num_d_vals);
	//	}
	//	X86SIMDType::M128(_) => {
	//		let start_idx = align_usize(num_f_vals, SIMD_ALIGNMENT_BYTES / 4);
	//		write!(cpp_code, "_mm_load_ps(&fVals[{}])", start_idx).expect("");
	//		return (num_i_vals, start_idx + 4, num_d_vals);
	//	}
	//	X86SIMDType::M128d(_) => {
	//		let start_idx = align_usize(num_d_vals, SIMD_ALIGNMENT_BYTES / 8);
	//		write!(cpp_code, "_mm_load_pd(&dVals[{}])", start_idx).expect("");
	//		return (num_i_vals, num_f_vals, start_idx + 2);
	//	}
	//	X86SIMDType::M128i(_) => {
	//		let start_idx = align_usize(num_i_vals, SIMD_ALIGNMENT_BYTES / 4);
	//		write!(cpp_code, "_mm_load_si128((const __m128i*)&iVals[{}])", start_idx).expect("");
	//		return (start_idx + 4, num_f_vals, num_d_vals);
	//	}
	//	X86SIMDType::M256(_) => {
	//		let start_idx = align_usize(num_f_vals, SIMD_ALIGNMENT_BYTES / 4);
	//		write!(cpp_code, "_mm256_load_ps(&fVals[{}])", start_idx).expect("");
	//		return (num_i_vals, start_idx + 8, num_d_vals);
	//	}
	//	X86SIMDType::M256d(_) => {
	//		let start_idx = align_usize(num_d_vals, SIMD_ALIGNMENT_BYTES / 8);
	//		write!(cpp_code, "_mm256_loadu_pd(&dVals[{}])", start_idx).expect("");
	//		return (num_i_vals, num_f_vals, start_idx + 4);
	//	}
	//	X86SIMDType::M256i(_) => {
	//		let start_idx = align_usize(num_i_vals, SIMD_ALIGNMENT_BYTES / 4);
	//		write!(cpp_code, "_mm256_loadu_si256((const __m256i*)&iVals[{}])", start_idx).expect("");
	//		return (start_idx + 8, num_f_vals, num_d_vals);
	//	}
	//}
}

pub fn generate_cpp_code_from_arm_codegen_ctx(ctx: &ARMSIMDCodegenCtx) -> (String, usize, usize, usize) {
	let mut cpp_code = String::with_capacity(32*1024);

	cpp_code.push_str("#include <arm_neon.h>\n");

	let mut num_i_vals : usize = 0;
	let mut num_f_vals : usize = 0;
	let mut num_d_vals : usize = 0;

	let return_type = ctx.get_return_type();
	let return_type_name = arm_simd_type_to_cpp_type_name(return_type);

	write!(&mut cpp_code, "extern \"C\" {} do_stuff(const int* iVals, const float* fVals, const double* dVals);\n", return_type_name).expect("");
	write!(&mut cpp_code, "{} do_stuff(const int* iVals, const float* fVals, const double* dVals) {{\n", return_type_name).expect("");

	for (ii, node) in ctx.intrinsics_sequence.iter().enumerate().rev() {
		match node {
			ARMSIMDCodegenNode::Immediate(base_type, i_val, _f_val) => {
				// TODO: Pick i_val or f_val or d_val as needed like in entry
				write!(&mut cpp_code, "\t{} var_{} = {};\n", arm_base_type_to_cpp_type_name(*base_type), ii, i_val).expect("");
			}
			ARMSIMDCodegenNode::ConstantImmediate(_) => {
				// Do nothing, this isn't a runtime value
			}
			ARMSIMDCodegenNode::Zero(node_type) => {
				// TODO: Should we do something other than "x = {}" ?
				write!(&mut cpp_code, "\t{} var_{} = {{}};\n", arm_simd_type_to_cpp_type_name(*node_type), ii).expect("");
			}
			ARMSIMDCodegenNode::Entry(entry_type) => {
				let (new_num_i_vals, new_num_f_vals, new_num_d_vals) =
					arm_generate_cpp_entry_code_for_type(&mut cpp_code, ii, *entry_type, num_i_vals, num_f_vals, num_d_vals);
				
				num_i_vals = new_num_i_vals;
				num_f_vals = new_num_f_vals;
				num_d_vals = new_num_d_vals;
				
				// TODO: Can we move this into the function? idk
				cpp_code.push_str(";\n");
			}
			ARMSIMDCodegenNode::Produced(intrinsic_node) => {
				if intrinsic_node.intrinsic.return_type == ARMSIMDType::Primitive(ARMBaseType::Void) {
					write!(&mut cpp_code, "\t{}(", intrinsic_node.intrinsic.intrinsic_name).expect("");
				}
				else {
					write!(&mut cpp_code, "\t{} var_{} = {}(", arm_simd_type_to_cpp_type_name(intrinsic_node.intrinsic.return_type),
						ii, intrinsic_node.intrinsic.intrinsic_name).expect("");
				}
				for (ref_ii, ref_idx) in intrinsic_node.references.iter().enumerate() {
					if ref_ii > 0 {
						cpp_code.push_str(", ");
					}

					if let ARMSIMDCodegenNode::ConstantImmediate(imm_val) = ctx.intrinsics_sequence[*ref_idx] {
						write!(&mut cpp_code, "{}", imm_val).expect("");
					}
					else {
						write!(&mut cpp_code, "var_{}", *ref_idx).expect("");
					}
				}
				cpp_code.push_str(");\n");
			}
			ARMSIMDCodegenNode::NoOp => { /*Do nothing*/ }
			ARMSIMDCodegenNode::Pending(_) => panic!("generating arm cpp code but node still pending")
		}
	}

	let return_node_idx = ctx.get_return_node_idx();
	write!(&mut cpp_code, "\treturn var_{};\n", return_node_idx).expect("");

	cpp_code.push_str("}\n");
	cpp_code.push_str("\n");

	return (cpp_code, num_i_vals, num_f_vals, num_d_vals);
}
