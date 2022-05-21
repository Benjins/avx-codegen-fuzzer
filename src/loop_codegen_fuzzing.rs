
use std::fmt::Write;

use crate::codegen_fuzzing::CodegenFuzzer;
use crate::rand::Rand;

use crate::exec_mem::ExecPage;


// TODO:
//enum LoopIntType {
//	U8,
//	U16,
//	U32,
//	U64
//}

pub struct LoopFuzzerCodeMetadata {
	// TODO: type
	loop_inner_stride : usize
}

pub struct LoopFuzzerThreadInput {
	pub thread_seed : u64
}

pub struct LoopFuzzer {
	outer_rng : Rand
}

#[derive(Clone, Debug)]
pub struct LoopFuzzerInputValues {
	pub vals : Vec<u32>
}

impl LoopFuzzerInputValues {
	pub fn write_to_str(&self) -> String {
		let mut out_str = String::with_capacity(4096);

		write!(out_str, "{}\n", self.vals.len()).expect("");
		for val in self.vals.iter() {
			write!(out_str, "{} ", val).expect("");
		}

		return out_str;
	}
}

#[derive(Clone, Debug)]
pub struct LoopFuzzerOutputValues {
	pub vals : Vec<u32>
}


#[derive(Clone, Copy, Debug)]
enum LoopCodegenValue {
	Register(usize),
	ConstantValue(u32)
}

impl LoopCodegenValue {
	pub fn write_to_code(&self, cpp_code: &mut String, do_and : bool) {
		if do_and {
			cpp_code.push_str("(");
		}
		
		match self {
			Self::Register(reg) => {
				write!(cpp_code, "r{}", reg).expect("");
			}
			Self::ConstantValue(imm_val) => {
				write!(cpp_code, "{}", imm_val).expect("");
			}
		}
		
		if do_and {
			cpp_code.push_str(" & 31)");
		}
	}
}

#[derive(Clone, Copy, Debug)]
enum LoopCodegenOp {
	Add,
	Sub,
	Mul,
	BitAnd,
	BitOr,
	BitXor,
	ShiftLeft,
	ShiftRight
}

fn get_op_symbol(op : &LoopCodegenOp) -> &'static str {
	match op {
		LoopCodegenOp::Add => "+",
		LoopCodegenOp::Sub => "-",
		LoopCodegenOp::Mul => "*",
		LoopCodegenOp::BitAnd => "&",
		LoopCodegenOp::BitOr => "|",
		LoopCodegenOp::BitXor => "^",
		LoopCodegenOp::ShiftLeft => "<<",
		LoopCodegenOp::ShiftRight => ">>"
	}
}

#[derive(Clone, Debug)]
struct LoopCodegenNode {
	op : LoopCodegenOp,
	dest_register : usize,
	src1 : LoopCodegenValue,
	src2 : LoopCodegenValue
}

impl LoopCodegenNode {
	pub fn write_to_code(&self, cpp_code: &mut String) {
		write!(cpp_code, "r{} = ", self.dest_register).expect("");
		
		self.src1.write_to_code(cpp_code, false);
		
		let op_symbol = get_op_symbol(&self.op);
		//println!("{:?} -> {}", self.op, op_symbol);
		write!(cpp_code, " {} ", op_symbol).expect("");
		
		let do_and = match self.op { LoopCodegenOp::ShiftLeft | LoopCodegenOp::ShiftRight => true, _ => false };
		self.src2.write_to_code(cpp_code, do_and);
		
		cpp_code.push_str(";\n");
	}
}

#[derive(Clone)]
pub struct LoopCodegenCtx {
	nodes : Vec<LoopCodegenNode>
}

const IMMEDIATE_VALUE_CHANCE_NUM : u32 = 1;
const IMMEDIATE_VALUE_CHANCE_DENOM : u32 = 4;

const NUM_REGISTERS : usize = 4;

impl LoopCodegenCtx {
	pub fn new(seed : u64) -> LoopCodegenCtx {
		let mut rng = Rand::new(seed);

		let num_nodes = rng.rand() % 10 + 5;
		
		let mut nodes = Vec::with_capacity(num_nodes as usize);
		for _ in 0..num_nodes {
			nodes.push(Self::get_random_node(NUM_REGISTERS, &mut rng));
		}

		return LoopCodegenCtx { nodes: nodes };
	}

	fn get_random_value(num_registers : usize, rng : &mut Rand) -> LoopCodegenValue {
		if (rng.rand() % IMMEDIATE_VALUE_CHANCE_DENOM) < IMMEDIATE_VALUE_CHANCE_NUM {
			LoopCodegenValue::ConstantValue(rng.rand())
		}
		else {
			LoopCodegenValue::Register(rng.rand_size() % num_registers)
		}
	}

	fn get_random_node(num_registers : usize, rng : &mut Rand) -> LoopCodegenNode {
		let op_decider = rng.rand() % 8;
		let op = match op_decider {
			0 => LoopCodegenOp::Add,
			1 => LoopCodegenOp::Sub,
			2 => LoopCodegenOp::Mul,
			3 => LoopCodegenOp::BitAnd,
			4 => LoopCodegenOp::BitOr,
			5 => LoopCodegenOp::BitXor,
			6 => LoopCodegenOp::ShiftLeft,
			7 => LoopCodegenOp::ShiftRight,
			_ => panic!("bad decider")
		};
		
		return LoopCodegenNode {
			op: op,
			dest_register: rng.rand_size() % num_registers,
			src1: Self::get_random_value(num_registers, rng),
			src2: Self::get_random_value(num_registers, rng)
		};
	}
	
	pub fn generate_cpp_code(&self) -> String {
		let mut cpp_code = String::with_capacity(32*1024);
		
		write!(&mut cpp_code, "extern \"C\" void do_stuff(const int* __restrict inputs, int* __restrict outputs, int count) {{\n").expect("");
		
		// TODO configure loop stride
		write!(&mut cpp_code, "\tfor (int i = 0; i < count - 3; i+= 4) {{\n").expect("");
		
		for ii in 0..NUM_REGISTERS {
			write!(&mut cpp_code, "\t\tunsigned int r{} = inputs[i + {}];\n", ii, ii).expect("");
		}

		// insert operations here
		for node in self.nodes.iter() {
			cpp_code.push_str("\t\t");
			node.write_to_code(&mut cpp_code);
		}

		for ii in 0..NUM_REGISTERS {
			write!(&mut cpp_code, "\t\toutputs[i + {}] = r{};\n", ii, ii).expect("");
		}

		write!(&mut cpp_code, "\t}}\n").expect("");
		
		write!(&mut cpp_code, "}}\n").expect("");
		
		return cpp_code;
	}
}

impl CodegenFuzzer<LoopFuzzerThreadInput, LoopCodegenCtx, LoopFuzzerCodeMetadata, LoopFuzzerInputValues, LoopFuzzerOutputValues> for LoopFuzzer {
	// Each of these will go on a thread, can contain inputs like
	// a parsed spec data, seed, flags, config, etc.
	fn new_fuzzer_state(input_data : Self::ThreadInput) -> Self {
		Self { outer_rng: Rand::new(input_data.thread_seed) }
	}

	// This generates some context struct that's basically analagous to the AST
	fn generate_ctx(&mut self) -> Self::CodegenCtx {
		Self::CodegenCtx::new(self.outer_rng.rand_u64())
	}

	// Turn the AST/context into actual CPP code, along with any metadata (i.e. number of values to pass for SIMD's iVals pointer, return value, etc.)
	fn generate_cpp_code(&self, ctx : &Self::CodegenCtx) -> (String, Self::CodeMeta) {
		//println!("---------CODE--------");
		let cpp_code = ctx.generate_cpp_code();
		//println!("{}", cpp_code);
		//println!("-----------------");

		// TODO: variable inner stride
		(cpp_code, LoopFuzzerCodeMetadata { loop_inner_stride: 4 })
	}

	fn generate_random_input(&self, _code_meta : &Self::CodeMeta) -> Self::FuzzerInput {
		// Meh, kinda wish we didn't need to just make a new one since it requires mutability
		let mut rng = Rand::default();

		let num_values = 32 + rng.rand() % 16;
		let mut values = Vec::with_capacity(num_values as usize);
		for _ in 0..num_values {
			values.push(rng.rand());
		}

		return LoopFuzzerInputValues {vals: values };
	}

	// uhh.....idk
	fn try_minimize<F: Fn(&Self, &Self::CodegenCtx) -> bool>(&self, _ctx: Self::CodegenCtx, _func: F) -> Option<Self::CodegenCtx> {
		todo!()
	}

	// Actually execute it: this is probably like local, but 
	fn execute(&self, exec_page : &ExecPage, _code_meta: &Self::CodeMeta, input : &Self::FuzzerInput) -> Self::FuzzerOutput {
		let mut output_vals = vec![0u32 ; input.vals.len()];
		
		exec_page.execute_with_u32_io(&input.vals[..], &mut output_vals[..]);
		
		return LoopFuzzerOutputValues { vals: output_vals };
	}

	fn are_outputs_the_same(&self, o1 : &Self::FuzzerOutput, o2 : &Self::FuzzerOutput) -> bool {
		o1.vals == o2.vals
	}
	
	fn save_input_to_string(&self, input : &Self::FuzzerInput) -> String {
		input.write_to_str()
	}
	
	fn num_inputs_per_codegen(&self) -> u32 {
		100
	}
}




