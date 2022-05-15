
use crate::exec_mem::ExecPage;

pub trait CodegenFuzzer<InputData, CtxType, CodeMetadata, RunInputs, RunOutputs> {
	// Different names yeah w/e, we can revisit this
	type ThreadInput = InputData;
	type CodegenCtx = CtxType;
	type CodeMeta = CodeMetadata;
	type FuzzerInput = RunInputs;
	type FuzzerOutput = RunOutputs;
	
	// Each of these will go on a thread, can contain inputs like
	// a parsed spec data, flags, config, etc.
	fn new_fuzzer_state(input_data : InputData) -> Self;

	// This generates some context struct that's basically analagous to the AST
	fn generate_ctx(&mut self) -> CtxType;

	// Turn the AST/context into actual CPP code, along with any metadata (i.e. number of values to pass for SIMD's iVals pointer
	fn generate_cpp_code(&self, ctx : &CtxType) -> (String, CodeMetadata);

	// Given the metadata about the code, generate a random input for it
	fn generate_random_input(&self, code_meta : &CodeMetadata) -> RunInputs;

	// uhh.....idk
	fn try_minimize<F: Fn(&Self, &CtxType) -> bool>(&self, ctx: CtxType, func: F) -> Option<CtxType>;

	// Actually execute it: this is probably like just locally run, but also maybe to an emulator or another machine
	fn execute(&self, exec_page : &ExecPage, code_meta : &CodeMetadata, inputs : &RunInputs) -> RunOutputs;

	fn are_outputs_the_same(&self, o1 : &RunOutputs, o2 : &RunOutputs) -> bool;
	
	fn save_input_to_string(&self, input: &RunInputs) -> String;
	
	fn num_inputs_per_codegen(&self) -> u32;
}






// Example usage:
// 