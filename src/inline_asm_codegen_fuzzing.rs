
use std::fmt::Write;
use std::collections::BTreeSet;

use crate::codegen_fuzzing::CodegenFuzzer;
use crate::rand::Rand;

use crate::exec_mem::ExecPage;


pub struct AsmFuzzerCodeMetadata {
	loop_stride : u32
}

pub struct AsmFuzzerThreadInput {
	pub thread_seed : u64
}

pub struct AsmFuzzer {
	outer_rng : Rand
}


#[derive(Clone, Debug)]
pub struct AsmFuzzerInputValues {
	pub vals : Vec<u64>
}

impl AsmFuzzerInputValues {
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
pub struct AsmFuzzerOutputValues {
	pub vals : Vec<u64>
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AsmRegister {
	RAX,
	RBX,
	RCX,
	RDX,
	RSI,
	RDI,
	R8,
	R9
}

impl AsmRegister {
	pub fn to_string(&self) -> &'static str {
		match self {
			AsmRegister::RAX => "rax",
			AsmRegister::RBX => "rbx",
			AsmRegister::RCX => "rcx",
			AsmRegister::RDX => "rdx",
			AsmRegister::RSI => "rsi",
			AsmRegister::RDI => "rdi",
			AsmRegister::R8 => "r8",
			AsmRegister::R9 => "r9"
		}
	}
	
	pub fn random(rng : &mut Rand) -> Self {
		let decider = rng.rand() % 8;
		match decider {
			0 => AsmRegister::RAX,
			1 => AsmRegister::RBX,
			2 => AsmRegister::RCX,
			3 => AsmRegister::RDX,
			4 => AsmRegister::RSI,
			5 => AsmRegister::RDI,
			6 => AsmRegister::R8,
			7 => AsmRegister::R9,
			_ => panic!("bad decider")
		}
	}
}

#[derive(Clone, Debug)]
enum AsmCodegenAsmValue {
	CVar(u32),
	AsmReg(AsmRegister)
}

impl AsmCodegenAsmValue {
	pub fn write_to_cpp_code(&self, code : &mut String) {
		match self {
			AsmCodegenAsmValue::CVar(var_idx) => {
				write!(code, "%[c_{}]", var_idx).expect("");
			}
			AsmCodegenAsmValue::AsmReg(reg) => {
				code.push_str(reg.to_string());
			}
		}
	}
}

#[derive(Clone, Debug)]
enum AsmCodegenOpcode {
	Lea,
	IMul,
	Mov,
	Xor
}

impl AsmCodegenOpcode {
	pub fn to_opcode_str(&self) -> &'static str {
		match *self {
			AsmCodegenOpcode::Lea => "lea",
			AsmCodegenOpcode::IMul  => "imul",
			AsmCodegenOpcode::Mov  => "mov",
			AsmCodegenOpcode::Xor => "xor"
		}
	}
}

#[derive(Clone, Debug)]
struct AsmCodegenAsmStmt {
	opcode : AsmCodegenOpcode,
	values : Vec<AsmCodegenAsmValue>,
	out_val_idx : usize, // TODO: Reference?
	in_val_indices : Vec<usize> // TODO: Slice?
}

impl AsmCodegenAsmStmt {
	pub fn write_to_cpp_code(&self, code : &mut String) {
		match self.opcode {
			AsmCodegenOpcode::Lea => {
				code.push_str("lea ");
				self.values[0].write_to_cpp_code(code);
				code.push_str(", [");
				self.values[1].write_to_cpp_code(code);
				code.push_str(" + ");
				self.values[2].write_to_cpp_code(code);
				code.push_str("]");
			}
			_ => {
				code.push_str(self.opcode.to_opcode_str());
				for (ii, val) in self.values.iter().enumerate() {
					code.push_str( if ii == 0 { " " } else { ", " } );
					val.write_to_cpp_code(code);
				}
			}
		}
	}
}

#[derive(Default, Clone, Debug)]
struct AsmCodegenNodeAsm {
	stmts : Vec<AsmCodegenAsmStmt>
	// TODO: Extra clobbers?
}

#[derive(Default, Clone, Debug)]
struct AsmCodegenRegConstraints {
	pub outputs : BTreeSet<u32>,
	pub inputs : BTreeSet<u32>,
	pub temps : BTreeSet<AsmRegister>
}

impl AsmCodegenRegConstraints {
	pub fn add_constraints_for_stmt(&mut self, stmt : &AsmCodegenAsmStmt) {
		for val in stmt.values.iter() {
			match val {
				AsmCodegenAsmValue::AsmReg(reg) => {
					self.temps.insert(*reg);
				}
				_ => { /*do nothing*/ }
			}
		}
		
		match stmt.values[stmt.out_val_idx] {
			AsmCodegenAsmValue::CVar(var_idx) => {
				self.outputs.insert(var_idx);
			}
			_ => { /*do nothing*/ }
		}
		
		for idx in stmt.in_val_indices.iter() {
			match stmt.values[*idx] {
				AsmCodegenAsmValue::CVar(var_idx) => {
					self.inputs.insert(var_idx);
				}
				_ => { /*do nothing*/ }
			}
		}
	}
}

impl AsmCodegenNodeAsm {
	pub fn write_to_cpp_code(&self, code : &mut String) {
		code.push_str("asm(");

		// asm code
		for stmt in self.stmts.iter() {
			code.push_str("\n\t\t\t\"");
			stmt.write_to_cpp_code(code);
			code.push_str("\\n\\t\"");
		}

		code.push_str("\n\t\t\t:");

		let mut reg_constraints = AsmCodegenRegConstraints::default();

		for stmt in self.stmts.iter() {
			reg_constraints.add_constraints_for_stmt(stmt);
		}

		// output constraints
		for (ii, output) in reg_constraints.outputs.iter().enumerate() {
			if ii != 0 { code.push_str(", "); }
			// TODO: Avoid early clobber constraint if possible
			let constraint = if reg_constraints.inputs.contains(output) { "+r" } else { "=&r" };
			write!(code, "[c_{}] \"{}\"(c_{})", output, constraint, output).expect("");
		}

		code.push_str("\n\t\t\t:");

		// input constraints
		{
			let mut needs_comma = false;
			for input in reg_constraints.inputs.iter() {
				// Input/Output combinations handled above, requires a different constraint
				if reg_constraints.outputs.contains(input) {
					continue;
				}
				if needs_comma { code.push_str(", "); }
				write!(code, "[c_{}] \"r\"(c_{})", input, input).expect("");
				needs_comma = true;
			}
		}

		code.push_str("\n\t\t\t:");

		// extra clobbers
		for (ii, tmp) in reg_constraints.temps.iter().enumerate() {
			if ii != 0 { code.push_str(", "); }
			write!(code, "\"{}\"", tmp.to_string()).expect("");
		}

		code.push_str("\t\t);");
	}
}

#[derive(Clone, Debug, Copy)]
enum AsmCodegenCppOp {
	Add,
	Mul,
	Shift(u32) // shift amount, so only 1 input
}

impl AsmCodegenCppOp {
	pub fn num_inputs(&self) -> usize {
		match *self {
			AsmCodegenCppOp::Add => 2,
			AsmCodegenCppOp::Mul => 2,
			AsmCodegenCppOp::Shift(_) => 1
		}
	}

	pub fn random_op(rng : &mut Rand) -> AsmCodegenCppOp {
		let decider = rng.rand() % 3;
		match decider {
			0 => AsmCodegenCppOp::Add,
			1 => AsmCodegenCppOp::Mul,
			2 => AsmCodegenCppOp::Shift(rng.rand() % 32),
			_ => panic!("bad decider")
		}
	}
}

#[derive(Clone, Debug)]
struct AsmCodegenNodeCpp {
	pub op : AsmCodegenCppOp,
	pub dest_var : u32,
	pub inputs : Vec<u32>
}

impl AsmCodegenNodeCpp {
	pub fn write_cpp_code(&self, code : &mut String) {
		write!(code, "c_{} = ", self.dest_var);
		match self.op {
			AsmCodegenCppOp::Add => {
				assert!(self.inputs.len() == 2);
				write!(code, "c_{} + c_{}", self.inputs[0], self.inputs[1]).expect("");
			}
			AsmCodegenCppOp::Mul => {
				assert!(self.inputs.len() == 2);
				write!(code, "c_{} * c_{}", self.inputs[0], self.inputs[1]).expect("");
			}
			AsmCodegenCppOp::Shift(shift_amount) => {
				assert!(self.inputs.len() == 1);
				write!(code, "c_{} << {}", self.inputs[0], shift_amount).expect("");
			}
		}
		code.push_str(";");
	}
}

#[derive(Clone, Debug)]
enum AsmCodegenNode {
	NoOp,
	//Pending,
	Asm(AsmCodegenNodeAsm),
	Cpp(AsmCodegenNodeCpp)
}

#[derive(Clone)]
pub struct AsmCodegenCtx {
	loop_stride : u32,
	nodes : Vec<AsmCodegenNode>
}


fn gen_vec_of_length_and_max_val(rng : &mut Rand, len : usize, max : u32) -> Vec<u32> {
	let mut vec = Vec::with_capacity(len);
	for _ in 0..len {
		vec.push(rng.rand() % max);
	}
	
	return vec;
}

impl AsmCodegenCtx {
	pub fn new(seed : u64) -> Self {
		let mut rng = Rand::new(seed);

		let loop_stride = rng.rand() % 8 + 4;

		let num_nodes = rng.rand() % 20 + 10;
		
		let mut written_tmp_registers = BTreeSet::new();
		let mut get_random_asm_value = |is_output, this_rng: &mut Rand| {
			let decider = this_rng.rand() % 2;
			// tmp register
			if (is_output || written_tmp_registers.len() > 0) && written_tmp_registers.len() < 6 && decider == 0 {
				if is_output {
					let reg = AsmRegister::random(this_rng);
					written_tmp_registers.insert(reg);
					return AsmCodegenAsmValue::AsmReg(reg);
				}
				else {
					// Pick random register in written_tmp_registers
					let idx = this_rng.rand_size() % written_tmp_registers.len();
					return AsmCodegenAsmValue::AsmReg(*written_tmp_registers.iter().nth(idx).unwrap());
				}
			}
			// C variable
			else {
				return AsmCodegenAsmValue::CVar(this_rng.rand() % loop_stride);
			}
		};
		
		let mut nodes = Vec::with_capacity(num_nodes as usize);
		for _ in 0..num_nodes {
			let decider = rng.rand() % 3;
			// inline asm
			if decider == 0 {
				let num_stmts = rng.rand() % 6 + 1;
				let mut stmts = Vec::with_capacity(num_stmts as usize);
				for _ in 0..num_stmts {
					
					let decider = rng.rand() % 4;
					
					let stmt = match decider {
						0 => {
							AsmCodegenAsmStmt {
								opcode: AsmCodegenOpcode::Lea,
								values: vec![get_random_asm_value(true, &mut rng), get_random_asm_value(false, &mut rng), get_random_asm_value(false, &mut rng)],
								out_val_idx: 0,
								in_val_indices: vec![1, 2]
							}
						}
						1 => {
							AsmCodegenAsmStmt {
								opcode: AsmCodegenOpcode::IMul,
								values: vec![get_random_asm_value(false, &mut rng), get_random_asm_value(false, &mut rng)],
								out_val_idx: 0,
								in_val_indices: vec![0, 1]
							}
						}
						2 => {
							AsmCodegenAsmStmt {
								opcode: AsmCodegenOpcode::Mov,
								values: vec![get_random_asm_value(true, &mut rng), get_random_asm_value(false, &mut rng)],
								out_val_idx: 0,
								in_val_indices: vec![1]
							}
						}
						3 => {
							AsmCodegenAsmStmt {
								opcode: AsmCodegenOpcode::Xor,
								values: vec![get_random_asm_value(false, &mut rng), get_random_asm_value(false, &mut rng)],
								out_val_idx: 0,
								in_val_indices: vec![0, 1]
							}
						}
						_ => { panic!("bad decider") }
					};
					
					stmts.push(stmt);
				}

				let asm = AsmCodegenNodeAsm {
					stmts: stmts
				};
				nodes.push(AsmCodegenNode::Asm(asm));
			}
			// cpp
			else {
				let op = AsmCodegenCppOp::random_op(&mut rng);
				let num_inputs = op.num_inputs();
				let cpp = AsmCodegenNodeCpp {
					op: op,
					dest_var: rng.rand() % loop_stride,
					inputs: gen_vec_of_length_and_max_val(&mut rng, num_inputs, loop_stride)
				};
				nodes.push(AsmCodegenNode::Cpp(cpp));
			}
		}

		return Self { loop_stride: loop_stride, nodes: nodes };
	}
	
	pub fn get_loop_stride(&self) -> u32 {
		self.loop_stride
	}
	
	pub fn generate_cpp_code(&self) -> String {
		let mut cpp_code = String::with_capacity(32*1024);
		
		write!(&mut cpp_code, "extern \"C\" void do_stuff(const long long* __restrict inputs, long long* __restrict outputs, int count) {{\n").expect("");
		
		// TODO configure loop stride
		write!(&mut cpp_code, "\tfor (int i = 0; i < count - {}; i+= {}) {{\n", self.loop_stride - 1, self.loop_stride).expect("");
		
		for ii in 0..self.loop_stride {
			write!(&mut cpp_code, "\t\tunsigned long long c_{} = inputs[i + {}];\n", ii, ii).expect("");
		}
		for node in self.nodes.iter() {
			match node {
				AsmCodegenNode::Cpp(cpp) => {
					cpp_code.push_str("\t\t");
					cpp.write_cpp_code(&mut cpp_code);
					cpp_code.push_str("\n");
				}
				AsmCodegenNode::Asm(asm) => {
					cpp_code.push_str("\t\t");
					asm.write_to_cpp_code(&mut cpp_code);
					cpp_code.push_str("\n");
				}
				AsmCodegenNode::NoOp => { /* do nothing, it's a no-op */ }
			}
		}

		for ii in 0..self.loop_stride {
			write!(&mut cpp_code, "\t\toutputs[i + {}] += c_{};\n", ii, ii).expect("");
		}

		write!(&mut cpp_code, "\t}}\n").expect("");
		
		write!(&mut cpp_code, "}}\n").expect("");
		
		return cpp_code;
	}
}

impl CodegenFuzzer<AsmFuzzerThreadInput, AsmCodegenCtx, AsmFuzzerCodeMetadata, AsmFuzzerInputValues, AsmFuzzerOutputValues> for AsmFuzzer {
	// Each of these will go on a thread, can contain inputs like
	// a parsed spec data, seed, flags, config, etc.
	fn new_fuzzer_state(input_data : Self::ThreadInput) -> Self {
		Self { outer_rng: Rand::new(input_data.thread_seed) }
	}

	// This generates some context struct that's basically analagous to the AST
	fn generate_ctx(&mut self) -> Self::CodegenCtx {
		let next_seed = self.outer_rng.rand_u64();
		return AsmCodegenCtx::new(next_seed);
	}

	// Turn the AST/context into actual CPP code, along with any metadata (i.e. number of values to pass for SIMD's iVals pointer, return value, etc.)
	fn generate_cpp_code(&self, ctx : &Self::CodegenCtx) -> (String, Self::CodeMeta) {
		let code = ctx.generate_cpp_code();
		//println!("----------Code------");
		//println!("{}", code);
		//println!("--------------------");
		return (code, AsmFuzzerCodeMetadata { loop_stride: ctx.get_loop_stride() })
	}

	fn generate_random_input(&self, code_meta : &Self::CodeMeta) -> Self::FuzzerInput {
		// Meh, kinda wish we didn't need to just make a new one since it requires mutability
		let mut rng = Rand::default();

		let num_values = 32 + rng.rand() % 32;
		let mut values = Vec::with_capacity(num_values as usize);
		for _ in 0..num_values {
			let val = match rng.rand() % 4 {
				0 => 0,
				1 => 1,
				2 => 0xFFFFFFFFFFFFFFFFu64,
				3 => rng.rand_u64(),
				_ => panic!("bad decider")
			};
			values.push(val);
		}

		return Self::FuzzerInput {vals: values };
	}

	// uhh.....idk
	fn try_minimize<F: Fn(&Self, &Self::CodegenCtx) -> bool>(&self, ctx: Self::CodegenCtx, func: F) -> Option<Self::CodegenCtx> {
		return None;
		//todo!()
	}

	// Actually execute it: this is probably like local, but 
	fn execute(&self, exec_page : &ExecPage, _code_meta: &Self::CodeMeta, input : &Self::FuzzerInput) -> Self::FuzzerOutput {
		let mut output_vals = vec![0u64 ; input.vals.len()];
		
		exec_page.execute_with_u64_io(&input.vals[..], &mut output_vals[..]);
		
		return Self::FuzzerOutput { vals: output_vals };
	}

	fn are_outputs_the_same(&self, o1 : &Self::FuzzerOutput, o2 : &Self::FuzzerOutput) -> bool {
		o1.vals == o2.vals
	}
	
	fn save_input_to_string(&self, input : &Self::FuzzerInput) -> String {
		input.write_to_str()
	}

	fn read_input_from_string(&self, _serial : &str) -> Self::FuzzerInput {
		todo!()
	}

	fn save_meta_to_string(&self, _meta: &Self::CodeMeta) -> String {
		todo!()
	}

	fn read_meta_from_string(&self, _serial: &str) -> Self::CodeMeta {
		todo!()
	}

	fn num_inputs_per_codegen(&self) -> u32 {
		1000
	}
}




