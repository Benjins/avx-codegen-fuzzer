
use std::fmt::Write;
use std::collections::{HashMap};

use crate::x86_intrinsics::*;
use crate::rand::Rand;

fn get_random_simd_etype(rng : &mut Rand, num_bits : u32) -> X86SIMDEType {
	let choice = rng.rand() % 11;
	match (choice, num_bits) {
		(0,_) => X86SIMDEType::Int8,
		(1,_) => X86SIMDEType::UInt8,
		(2,_) => X86SIMDEType::Int16,
		(3,_) => X86SIMDEType::UInt16,
		(4,_) => X86SIMDEType::Int32,
		(5,_) => X86SIMDEType::UInt32,
		(6,_) => X86SIMDEType::Int64,
		(7,_) => X86SIMDEType::UInt64,
		(8,_) => X86SIMDEType::Float32,
		(9,_) => X86SIMDEType::Float64,
		(10,64) => X86SIMDEType::M64,
		(10,128) => X86SIMDEType::M128,
		(10,256) => X86SIMDEType::M256,
		_ => panic!("Bad call to get_random_simd_etype({},{})", choice, num_bits)
	}
}

fn get_random_simd_type(rng : &mut Rand) -> X86SIMDType {
	let choice = rng.rand() % 7;
	match choice {
		0 => X86SIMDType::M64  (get_random_simd_etype(rng,  64)),
		1 => X86SIMDType::M128 (get_random_simd_etype(rng, 128)),
		2 => X86SIMDType::M128d(get_random_simd_etype(rng, 128)),
		3 => X86SIMDType::M128i(get_random_simd_etype(rng, 128)),
		4 => X86SIMDType::M256 (get_random_simd_etype(rng, 256)),
		5 => X86SIMDType::M256d(get_random_simd_etype(rng, 256)),
		6 => X86SIMDType::M256i(get_random_simd_etype(rng, 256)),
		_ => panic!("unimplemented")
	}
}



#[derive(Debug, Clone)]
pub struct X86SIMDCodegenIntrinsic {
	pub intrinsic : X86SIMDIntrinsic,
	pub references : Vec<usize>
}

#[derive(Debug, Clone)]
pub struct X86SIMDOptBaitNode {
	pub intrinsic : X86SIMDIntrinsic,
	pub node_idx : usize,
	pub mask : Vec<u8>
}

#[derive(Debug, Clone)]
pub enum X86SIMDCodegenNode {
	Immediate(X86BaseType, i64, f64),
	ConstantImmediate(X86BaseType, u32),
	Entry(X86SIMDType),
	Zero(X86SIMDType),
	Produced(X86SIMDCodegenIntrinsic),
	Pending(X86SIMDType),
	NoOp, // Used for minimization
	OptBait(X86SIMDOptBaitNode) // Used for opt-baiting
}

#[derive(Default, Clone)]
pub struct X86SIMDCodegenCtx {
	// 0 is the last, and it goes backward chronologically
	pub intrinsics_sequence : Vec<X86SIMDCodegenNode>,

	// For a given type, track all the node indices that produce that type
	pub type_to_ref_idx : HashMap<X86SIMDType, Vec<usize>>,
	
	// Some RNG state
	rng : Rand
}

const REUSE_NODE_IDX_DENOM : u32 = 6;
const REUSE_NODE_IDX_NUM : u32 = 1;

impl X86SIMDCodegenCtx {
	pub fn new(seed : u64) -> X86SIMDCodegenCtx {
		X86SIMDCodegenCtx {
			intrinsics_sequence: Vec::new(),
			type_to_ref_idx: HashMap::new(),
			rng: Rand::new(seed)
		}
	}
	
	pub fn get_ref_of_type(&mut self, ref_type : X86SIMDType, before_idx : usize) -> usize {
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
		if let X86SIMDType::ConstantImmediate(base_type, imm_size) = ref_type {
			self.intrinsics_sequence.push(X86SIMDCodegenNode::ConstantImmediate(base_type, self.rng.rand() % (1 << imm_size)));
		}
		else {
			self.intrinsics_sequence.push(X86SIMDCodegenNode::Pending(ref_type));
		}
		
		// Convert mask to U32...bah
		let underlying_type = get_underlying_simd_type(ref_type);
		let ref_indices: &mut Vec<usize> = 
			self.type_to_ref_idx.entry(underlying_type).or_insert_with(|| Vec::<usize>::with_capacity(4));

		ref_indices.push(new_ref_idx);
		
		return new_ref_idx;
	}
	
	pub fn maybe_get_node_of_type(&self, ref_type : X86SIMDType, before_idx : usize, not_idx : usize) -> Option<usize> {
		if let Some(ref_indices) = self.type_to_ref_idx.get(&ref_type) {
			for ref_idx in ref_indices {
				if *ref_idx > before_idx && *ref_idx != not_idx {
					return Some(*ref_idx);
				}
			}
		}
		
		return None;
	}

	pub fn get_type_of_pending_node(&self, node_idx : usize) -> Option<X86SIMDType> {
		match &self.intrinsics_sequence[node_idx] {
			X86SIMDCodegenNode::Immediate(_,_,_) => None,
			X86SIMDCodegenNode::Entry(_) => panic!("this shouldn't happen"),
			X86SIMDCodegenNode::ConstantImmediate(_,_) => None,
			X86SIMDCodegenNode::Produced(_) => None,
			X86SIMDCodegenNode::Zero(_) => None,
			X86SIMDCodegenNode::Pending(node_type) => Some(*node_type),
			X86SIMDCodegenNode::NoOp => None,
			X86SIMDCodegenNode::OptBait(_) => None
		}
	}
	
	pub fn get_num_nodes(&self) -> usize {
		return self.intrinsics_sequence.len();
	}
	
	pub fn _debug_print(&self) {
		for node in self.intrinsics_sequence.iter() {
			print!("Node {:?}\n", node);
		}
	}
	
	pub fn maybe_get_produced_node(&self, idx : usize) -> Option<&X86SIMDCodegenIntrinsic> {
		if let X86SIMDCodegenNode::Produced(ref intrinsic_node) = &self.intrinsics_sequence[idx] {
			Some(intrinsic_node)
		}
		else {
			None
		}
	}
	
	pub fn maybe_get_produced_node_mut(&mut self, idx : usize) -> Option<&mut X86SIMDCodegenIntrinsic> {
		if let X86SIMDCodegenNode::Produced(ref mut intrinsic_node) = &mut self.intrinsics_sequence[idx] {
			Some(intrinsic_node)
		}
		else {
			None
		}
	}
	
	pub fn is_node_produced(&self, idx : usize) -> bool {
		if let X86SIMDCodegenNode::Produced(_) = &self.intrinsics_sequence[idx] {
			true
		}
		else {
			false
		}
	}
	
	pub fn produce_for_idx(&mut self, idx : usize, node_intrinsic : X86SIMDCodegenIntrinsic) {
		if let X86SIMDCodegenNode::Pending(_node_type) = self.intrinsics_sequence[idx] {
			// TODO: Needs to take Mask types into account
			//assert!(node_type == node_intrinsic.intrinsic.return_type);
			self.intrinsics_sequence[idx] = X86SIMDCodegenNode::Produced(node_intrinsic);
		}
		else {
			panic!("node at index {} has already been produced", idx);
		}
	}
	
	pub fn mark_node_as_entry(&mut self, node_idx : usize) {
		match self.intrinsics_sequence[node_idx] {
			X86SIMDCodegenNode::Pending(node_type) => self.intrinsics_sequence[node_idx] = X86SIMDCodegenNode::Entry(node_type),
			_ => panic!("this shouldn't happen")
		}
	}
	
	pub fn mark_node_as_immediate(&mut self, node_idx : usize, imm_type : X86BaseType) {
		match self.intrinsics_sequence[node_idx] {
			// TODO: Pick actual numbers
			X86SIMDCodegenNode::Pending(node_type) => {
				match node_type {
					X86SIMDType::Primitive(base_type) => assert!(base_type == imm_type),
					_ => panic!("bad type in mark_node_as_immediate {:?}", node_type)
				}
				self.intrinsics_sequence[node_idx] = X86SIMDCodegenNode::Immediate(imm_type, 0, 0.0);
			}
			_ => panic!("this shouldn't happen")
		}
	}
	
	pub fn mark_node_as_noop(&mut self, node_idx : usize) {
		match &self.intrinsics_sequence[node_idx] {
			X86SIMDCodegenNode::Produced(intrinsic_node) => {
				let ret_type = get_underlying_simd_type(intrinsic_node.intrinsic.return_type);
				
				// Remove from type_to_ref_idx as well
				let ref_indices = self.type_to_ref_idx.get(&ret_type).unwrap();
				print!("Remove ref index {} for type {:?}\n", node_idx, ret_type);
				let index = ref_indices.iter().position(|x| *x == node_idx).unwrap();
				self.type_to_ref_idx.get_mut(&ret_type).unwrap().remove(index);
				
				self.intrinsics_sequence[node_idx] = X86SIMDCodegenNode::NoOp;
			}
			// TODO: We can't yet do this because it would potentially screw up input
			// We can do it for crash bugs, but...yeah
			X86SIMDCodegenNode::Entry(_) => { /*self.intrinsics_sequence[node_idx] = X86SIMDCodegenNode::NoOp;*/ }
			X86SIMDCodegenNode::Zero(node_type) => {
				let node_type = get_underlying_simd_type(*node_type);
				
				// Remove from type_to_ref_idx as well
				let index = self.type_to_ref_idx.get(&node_type).unwrap().iter().position(|x| *x == node_idx).unwrap();
				self.type_to_ref_idx.get_mut(&node_type).unwrap().remove(index);
				
				self.intrinsics_sequence[node_idx] = X86SIMDCodegenNode::NoOp;
			}
			_ => panic!("this shouldn't happen")
		}
	}
	
	pub fn mark_node_as_zero(&mut self, node_idx : usize) {
		if let X86SIMDCodegenNode::Pending(node_type) = self.intrinsics_sequence[node_idx] {
			self.intrinsics_sequence[node_idx] = X86SIMDCodegenNode::Zero(node_type);
		}
		else {
			panic!("node at index {} has already been produced", node_idx);
		}
	}
	
	pub fn get_return_type_old_dont_use(&self) -> X86SIMDType {
		if let X86SIMDCodegenNode::Produced(intrinsic_node) = &self.intrinsics_sequence[0] {
			return intrinsic_node.intrinsic.return_type;
		}
		else {
			panic!("return node has not been produced when calling get_return_type");
		}
	}
	
	pub fn get_type_of_node(&self, node_idx : usize) -> X86SIMDType {
		match &self.intrinsics_sequence[node_idx] {
			X86SIMDCodegenNode::Produced(intrinsic_node) => { return intrinsic_node.intrinsic.return_type; }
			X86SIMDCodegenNode::Entry(node_type) => { return *node_type; }
			X86SIMDCodegenNode::Zero(node_type) => { return *node_type; }
			_ => { panic!("Bad node index in get_type_of_node"); }
		}
	}

	pub fn get_return_node_idx(&self) -> usize {
		let mut return_node_idx = 0;
		while return_node_idx < self.intrinsics_sequence.len() && matches!(self.intrinsics_sequence[return_node_idx], X86SIMDCodegenNode::OptBait(_)) {
			return_node_idx += 1;
		}
		
		if return_node_idx >= self.intrinsics_sequence.len() {
			print!("Intrinsics sequence:\n{:?}\n", &self.intrinsics_sequence);
			panic!("bad codegen ctx: could not find return node");
		}
		
		return return_node_idx;
	}
	
	pub fn get_return_type(&self) -> X86SIMDType {
		let return_node_idx = self.get_return_node_idx();

		let return_type = if let X86SIMDCodegenNode::Produced(node_intrinsic) = &self.intrinsics_sequence[return_node_idx] {
			node_intrinsic.intrinsic.return_type
		}
		else if let X86SIMDCodegenNode::Entry(node_type) = &self.intrinsics_sequence[return_node_idx] {
			*node_type
		}
		else if let X86SIMDCodegenNode::Zero(node_type) = &self.intrinsics_sequence[return_node_idx] {
			*node_type
		}
		else {
			print!("Return node:\n{:?}\n", &self.intrinsics_sequence[return_node_idx]);
			panic!("bad return node")
		};
		
		return return_type;
	}
}

pub fn generate_codegen_ctx(ctx : &mut X86SIMDCodegenCtx, intrinsics_by_type : &HashMap<X86SIMDType, Vec<X86SIMDIntrinsic>>) {
	let mut ending_type = get_random_simd_type(&mut ctx.rng);
	while !intrinsics_by_type.contains_key(&ending_type) {
		ending_type = get_random_simd_type(&mut ctx.rng);
	}

	let _ = ctx.get_ref_of_type(ending_type, 0);

	//const NUM_NODE_ITERATIONS : usize = 100;
	//const NUM_NODE_ITERATIONS : usize = 60;//35;
	let num_node_iterations : usize = 40 + (ctx.rng.rand_size() % 100);
	//const CHANCE_FOR_ZERO_NODE : f32 = 0.01;
	let chance_for_zero_node : f32 = match (ctx.rng.rand() % 4) { 0 => 0.0001, 1 => 0.001, 2 => 0.01, 3 => 0.02, _ => panic!("") };

	//for ii in 0..NUM_NODE_ITERATIONS {
	for ii in 0..num_node_iterations {
		if ii >= ctx.get_num_nodes() {
			let _ = ctx.get_ref_of_type(ending_type, ii);
		}

		if let Some(node_type) = ctx.get_type_of_pending_node(ii) {
			// Convert MASK to uint32 because...idk gotta handle it better
			let node_type = get_underlying_simd_type(node_type);

			//if ii > 0 && ctx.rng.randf() < CHANCE_FOR_ZERO_NODE {
			if ii > 0 && ctx.rng.randf() < chance_for_zero_node {
				ctx.mark_node_as_zero(ii);
			}
			else {
				let intrinsics_for_type = intrinsics_by_type.get(&node_type);
				if let Some(intrinsics_for_type) = intrinsics_for_type {
					let intrinsic_to_use = &intrinsics_for_type[ctx.rng.rand_size() % intrinsics_for_type.len()];

					let mut node_intrinsic = X86SIMDCodegenIntrinsic {
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
				else if let X86SIMDType::Primitive(prim_type) = node_type {
					ctx.mark_node_as_immediate(ii, prim_type);
				}
				else {
					panic!("bad type {:?}", node_type);
				}
			}
		}
	}
	
	//for ii in NUM_NODE_ITERATIONS..ctx.get_num_nodes() {
	for ii in num_node_iterations..ctx.get_num_nodes() {
		if ctx.get_type_of_pending_node(ii).is_some() {
			ctx.mark_node_as_entry(ii);
		}
	}
}

fn align_usize(val : usize, alignment : usize) -> usize {
	(val + alignment - 1) / alignment * alignment
}

fn generate_cpp_entry_code_for_type(cpp_code: &mut String, var_idx : usize, entry_type : X86SIMDType, num_i_vals : usize, num_f_vals : usize, num_d_vals : usize) -> (usize, usize, usize) {
	write!(cpp_code, "\t{} var_{} = ", simd_type_to_cpp_type_name(entry_type), var_idx).expect("");

	// It's possible that M64/M128 have less strict alignment needs, but let's just do this
	const SIMD_ALIGNMENT_BYTES : usize = 32;

	match entry_type {
		X86SIMDType::Primitive(base_type) => {
			match base_type {
				X86BaseType::Int8 => {
					write!(cpp_code, "(char)(iVals[{}])", num_i_vals).expect("");
					return (num_i_vals + 1, num_f_vals, num_d_vals);
				}
				X86BaseType::UInt8 => {
					write!(cpp_code, "(unsigned char)(iVals[{}])", num_i_vals).expect("");
					return (num_i_vals + 1, num_f_vals, num_d_vals);
				}
				X86BaseType::Int16 => {
					write!(cpp_code, "(short)(iVals[{}])", num_i_vals).expect("");
					return (num_i_vals + 1, num_f_vals, num_d_vals);
				}
				X86BaseType::UInt16 => {
					write!(cpp_code, "(unsigned short)(iVals[{}])", num_i_vals).expect("");
					return (num_i_vals + 1, num_f_vals, num_d_vals);
				}
				X86BaseType::Int32 => {
					write!(cpp_code, "(int)(iVals[{}])", num_i_vals).expect("");
					return (num_i_vals + 1, num_f_vals, num_d_vals);
				}
				X86BaseType::UInt32 => {
					write!(cpp_code, "(unsigned int)(iVals[{}])", num_i_vals).expect("");
					return (num_i_vals + 1, num_f_vals, num_d_vals);
				}
				X86BaseType::Int64 => {
					write!(cpp_code, "(long long)(iVals[{}])", num_i_vals).expect("");
					return (num_i_vals + 1, num_f_vals, num_d_vals);
				}
				X86BaseType::UInt64 => {
					write!(cpp_code, "(unsigned long long)(iVals[{}])", num_i_vals).expect("");
					return (num_i_vals + 1, num_f_vals, num_d_vals);
				}
				X86BaseType::Float32 => {
					write!(cpp_code, "fVals[{}]", num_f_vals).expect("");
					return (num_i_vals, num_f_vals + 1, num_d_vals);
				}
				X86BaseType::Float64 => {
					write!(cpp_code, "dVals[{}]", num_d_vals).expect("");
					return (num_i_vals, num_f_vals, num_d_vals + 1);
				}
				_ => panic!("void or bad base type")
			}
		}
		X86SIMDType::ConstantImmediate(_, _) => { panic!("Immediate") }
		X86SIMDType::M64(_) => {
			// TODO: Don't broadcast?
			let start_idx = align_usize(num_i_vals, SIMD_ALIGNMENT_BYTES / 4);
			write!(cpp_code, "_mm_set1_pi32(iVals[{}])", start_idx).expect("");
			return (start_idx + 2, num_f_vals, num_d_vals);
		}
		X86SIMDType::M128(_) => {
			let start_idx = align_usize(num_f_vals, SIMD_ALIGNMENT_BYTES / 4);
			write!(cpp_code, "_mm_load_ps(&fVals[{}])", start_idx).expect("");
			return (num_i_vals, start_idx + 4, num_d_vals);
		}
		X86SIMDType::M128d(_) => {
			let start_idx = align_usize(num_d_vals, SIMD_ALIGNMENT_BYTES / 8);
			write!(cpp_code, "_mm_load_pd(&dVals[{}])", start_idx).expect("");
			return (num_i_vals, num_f_vals, start_idx + 2);
		}
		X86SIMDType::M128i(_) => {
			let start_idx = align_usize(num_i_vals, SIMD_ALIGNMENT_BYTES / 4);
			write!(cpp_code, "_mm_load_si128((const __m128i*)&iVals[{}])", start_idx).expect("");
			return (start_idx + 4, num_f_vals, num_d_vals);
		}
		X86SIMDType::M256(_) => {
			let start_idx = align_usize(num_f_vals, SIMD_ALIGNMENT_BYTES / 4);
			write!(cpp_code, "_mm256_load_ps(&fVals[{}])", start_idx).expect("");
			return (num_i_vals, start_idx + 8, num_d_vals);
		}
		X86SIMDType::M256d(_) => {
			let start_idx = align_usize(num_d_vals, SIMD_ALIGNMENT_BYTES / 8);
			write!(cpp_code, "_mm256_loadu_pd(&dVals[{}])", start_idx).expect("");
			return (num_i_vals, num_f_vals, start_idx + 4);
		}
		X86SIMDType::M256i(_) => {
			let start_idx = align_usize(num_i_vals, SIMD_ALIGNMENT_BYTES / 4);
			write!(cpp_code, "_mm256_loadu_si256((const __m256i*)&iVals[{}])", start_idx).expect("");
			return (start_idx + 8, num_f_vals, num_d_vals);
		}
	}
}

pub fn generate_cpp_code_from_codegen_ctx(ctx: &X86SIMDCodegenCtx) -> (String, usize, usize, usize) {
	let mut cpp_code = String::with_capacity(32*1024);

	cpp_code.push_str("#define _CRT_SECURE_NO_WARNINGS\n\n");
	cpp_code.push_str("#include <immintrin.h>\n");

	// Shims
	cpp_code.push_str("#if defined(_MSC_VER)\n");
	cpp_code.push_str("#define _mm_cvtsi128_si64x _mm_cvtsi128_si64\n");
	cpp_code.push_str("#define _mm_cvtsi64x_si128 _mm_cvtsi64_si128\n");
	cpp_code.push_str("#elif defined(__clang__)\n");
	cpp_code.push_str("#define _mm_cvtsi64x_si128 _mm_cvtsi64_si128\n");
	cpp_code.push_str("#define _mm_cvtsi64x_sd _mm_cvtsi64_sd\n");
	cpp_code.push_str("#define _mm_cvtsi128_si64x _mm_cvtsi128_si64\n");
	cpp_code.push_str("#define _mm_cvtsd_si64x _mm_cvtsd_si64\n");
	cpp_code.push_str("#define _mm_cvttsd_si64x _mm_cvttsd_si64\n");
	cpp_code.push_str("#endif\n");
	cpp_code.push_str("\n");

	let mut num_i_vals : usize = 0;
	let mut num_f_vals : usize = 0;
	let mut num_d_vals : usize = 0;

	let return_type = ctx.get_return_type();
	let return_type_name = simd_type_to_cpp_type_name(return_type);

	cpp_code.push_str("#if defined(_MSC_VER)\n");
	cpp_code.push_str("__declspec(noinline)\n");
	cpp_code.push_str("#elif defined(__clang__)\n");
	cpp_code.push_str("__attribute__((noinline))\n");
	cpp_code.push_str("#else\n");
	cpp_code.push_str("#error \"Not supported compiler, need to add branch for no-inline attribute\"\n");
	cpp_code.push_str("#endif\n");

	write!(&mut cpp_code, "extern \"C\" {} do_stuff(const int* iVals, const float* fVals, const double* dVals);\n", return_type_name).expect("");
	write!(&mut cpp_code, "{} do_stuff(const int* iVals, const float* fVals, const double* dVals) {{\n", return_type_name).expect("");

	for (ii, node) in ctx.intrinsics_sequence.iter().enumerate().rev() {
		match node {
			X86SIMDCodegenNode::Immediate(base_type, i_val, _f_val) => {
				// TODO: Pick i_val or f_val or d_val as needed like in entry
				write!(&mut cpp_code, "\t{} var_{} = {};\n", base_type_to_cpp_type_name(*base_type), ii, i_val).expect("");
			}
			X86SIMDCodegenNode::ConstantImmediate(_,_) => {
				// Do nothing, this isn't a runtime value
			}
			X86SIMDCodegenNode::Zero(node_type) => {
				// TODO: Should we do something other than "x = {}" ?
				write!(&mut cpp_code, "\t{} var_{} = {{}};\n", simd_type_to_cpp_type_name(*node_type), ii).expect("");
			}
			X86SIMDCodegenNode::Entry(entry_type) => {
				let (new_num_i_vals, new_num_f_vals, new_num_d_vals) =
					generate_cpp_entry_code_for_type(&mut cpp_code, ii, *entry_type, num_i_vals, num_f_vals, num_d_vals);
				
				num_i_vals = new_num_i_vals;
				num_f_vals = new_num_f_vals;
				num_d_vals = new_num_d_vals;
				
				// TODO: Can we move this into the function? idk
				cpp_code.push_str(";\n");
			}
			X86SIMDCodegenNode::Produced(intrinsic_node) => {
				if intrinsic_node.intrinsic.return_type == X86SIMDType::Primitive(X86BaseType::Void) {
					write!(&mut cpp_code, "\t{}(", intrinsic_node.intrinsic.intrinsic_name).expect("");
				}
				else {
					write!(&mut cpp_code, "\t{} var_{} = {}(", simd_type_to_cpp_type_name(intrinsic_node.intrinsic.return_type),
						ii, intrinsic_node.intrinsic.intrinsic_name).expect("");
				}
				for (ref_ii, ref_idx) in intrinsic_node.references.iter().enumerate() {
					if ref_ii > 0 {
						cpp_code.push_str(", ");
					}

					if let X86SIMDCodegenNode::ConstantImmediate(_, imm_val) = ctx.intrinsics_sequence[*ref_idx] {
						write!(&mut cpp_code, "{}", imm_val).expect("");
					}
					else {
						write!(&mut cpp_code, "var_{}", *ref_idx).expect("");
					}
				}
				cpp_code.push_str(");\n");
			}
			X86SIMDCodegenNode::NoOp => { /*Do nothing*/ }
			X86SIMDCodegenNode::OptBait(opt_bait_node) => {
				
				// __m128i var_33 = _mm_load_si128((const __m128i*)&iVals[16]);
				// __m256i var_32 = _mm256_loadu_si256((const __m256i*)&iVals[24]);
				
				let load_func = if matches!(opt_bait_node.intrinsic.return_type, X86SIMDType::M128i(_)) {
					"_mm_load_si128"
				}
				else if matches!(opt_bait_node.intrinsic.return_type, X86SIMDType::M256i(_)) {
					"_mm256_loadu_si256"
				}
				else {
					panic!("bad intrinsic return type")
				};
				
				// Bah
				let mask_type = if matches!(opt_bait_node.intrinsic.return_type, X86SIMDType::M128i(_)) {
					"__m128i"
				}
				else if matches!(opt_bait_node.intrinsic.return_type, X86SIMDType::M256i(_)) {
					"__m256i"
				}
				else {
					panic!("bad intrinsic return type")
				};
				
				write!(&mut cpp_code, "\talignas(64) unsigned char opt_bait_mask_{}_bytes[] = {{ ", ii).expect("");
				for byte_val in opt_bait_node.mask.iter() {
					write!(&mut cpp_code, "{},", byte_val).expect("");
				}
				write!(&mut cpp_code, "}};\n").expect("");
				write!(&mut cpp_code, "\t{} opt_bait_mask_{} = {}((const {}*)opt_bait_mask_{}_bytes);\n", mask_type, ii, load_func, mask_type, ii).expect("");
				write!(&mut cpp_code, "\tvar_{} = {}(var_{}, opt_bait_mask_{});\n", opt_bait_node.node_idx, opt_bait_node.intrinsic.intrinsic_name, opt_bait_node.node_idx, ii).expect("");
			}
			X86SIMDCodegenNode::Pending(_) => panic!("generating cpp code but node still pending")
		}
	}

	let return_node_idx = ctx.get_return_node_idx();
	write!(&mut cpp_code, "\treturn var_{};\n", return_node_idx).expect("");

	cpp_code.push_str("}\n");
	cpp_code.push_str("\n");
	
	//cpp_code.push_str("int main() {\n");
	//
	//write!(&mut cpp_code, "\talignas(64) int i_vals[{}] = {{}};\n", std::cmp::max(1, num_i_vals)).expect("");
	//write!(&mut cpp_code, "\tfor (int i = 0; i < {}; i++) {{ scanf(\"%d\", &i_vals[i]); }}\n", num_i_vals).expect("");
	//
	//write!(&mut cpp_code, "\talignas(64) float f_vals[{}] = {{}};\n", std::cmp::max(1, num_f_vals)).expect("");
	//write!(&mut cpp_code, "\tfor (int i = 0; i < {}; i++) {{ scanf(\"%f\", &f_vals[i]); }}\n", num_f_vals).expect("");
	//
	//write!(&mut cpp_code, "\talignas(64) double d_vals[{}] = {{}};\n", std::cmp::max(1, num_d_vals)).expect("");
	//write!(&mut cpp_code, "\tfor (int i = 0; i < {}; i++) {{ scanf(\"%lf\", &d_vals[i]); }}\n", num_d_vals).expect("");
	//
	//write!(&mut cpp_code, "\t{} ret = do_stuff(i_vals, f_vals, d_vals);\n", return_type_name).expect("");
	//
	//cpp_code.push_str("\talignas(64) unsigned char dest_buff[sizeof(ret)] = {};\n");
	//cpp_code.push_str("\tmemcpy(dest_buff, &ret, sizeof(ret));\n");
	//
	//cpp_code.push_str("\tfor (int i = 0; i < sizeof(dest_buff); i++) {\n");
	//cpp_code.push_str("\t\tprintf(\"%02X\\n\", dest_buff[i]);\n");
	//cpp_code.push_str("\t}\n");
	//
	//cpp_code.push_str("\treturn 0;\n");
	//cpp_code.push_str("}\n");
	
	return (cpp_code, num_i_vals, num_f_vals, num_d_vals);
}


