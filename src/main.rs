
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sha2::{Sha256, Digest};

mod rand;
use rand::Rand;

mod compilation_config;
use compilation_config::{test_generated_code_compilation, test_generated_code_runtime, parse_compiler_config};
use compilation_config::{TestCompilation, TestRuntime, GenCodeResult, GenCodeFuzzMode};

mod parse_spec;
use parse_spec::parse_intel_intrinsics_xml;

// Kinda just need everything here
mod intrinsics;
use intrinsics::*;

mod codegen_ctx;
use codegen_ctx::{X86SIMDCodegenCtx, generate_cpp_code_from_codegen_ctx, generate_codegen_ctx};

fn check_minimized_gen_code(codegen_ctx : &X86SIMDCodegenCtx, expected_result : &GenCodeResult, compilation_tests : &Vec<TestCompilation>, runtime_tests : &Vec<TestRuntime>) -> bool {
	let (cpp_code, _, _, _) = generate_cpp_code_from_codegen_ctx(codegen_ctx);

	let mut input : Option<&str> = None;
	match expected_result {
		GenCodeResult::RuntimeFailure(expected_input, _) => {  input = Some(expected_input); }
		GenCodeResult::RuntimeDiff(expected_input) => {  input = Some(expected_input); }
		_ => { }
	}

	let res = test_generated_code_compilation(&cpp_code, compilation_tests);
	
	if let Some(input) = input {
		if matches!(res, GenCodeResult::Success) {
			let res = test_generated_code_runtime(runtime_tests, input);
			return std::mem::discriminant(&res) == std::mem::discriminant(expected_result);
		}
		
		// If the compile failed, but we were minimizing a runtime issue, then this is introducing a new issue
		// so don't accept the minimization
		return false;
	}
	else {
		// TODO: We could be more strict and only consider it a correct minimization if we had the same error code,
		// or similar ouptut in stderr, or something. But nah.
		return std::mem::discriminant(&res) == std::mem::discriminant(expected_result);
	}
}

pub fn minimize_gen_code(codegen_ctx : &X86SIMDCodegenCtx, expected_result : &GenCodeResult, compilation_tests : &Vec<TestCompilation>, runtime_tests : &Vec<TestRuntime>) -> X86SIMDCodegenCtx {
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
					if check_minimized_gen_code(&new_ctx, expected_result, compilation_tests, runtime_tests) {
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

fn get_hex_hash_of_bytes(input : &[u8]) -> String {
	let mut hasher = Sha256::new();
	hasher.update(input);
	let digest = hasher.finalize();
	hex::encode(digest)
}

fn save_out_failure_info(original_ctx : &X86SIMDCodegenCtx, min_ctx : &X86SIMDCodegenCtx, result : &GenCodeResult) {
	let (orig_code,_,_,_) = generate_cpp_code_from_codegen_ctx(original_ctx);
	let (min_code,_,_,_) = generate_cpp_code_from_codegen_ctx(min_ctx);

	match result {
		GenCodeResult::CompilerTimeout => {
			let min_hex_hash_full = get_hex_hash_of_bytes(min_code.as_bytes());
			let min_hex_hash = &min_hex_hash_full[0..10];
			let orig_code_filename = format!("fuzz_issues/compiler_timeouts/{}_orig.cpp", min_hex_hash);
			let min_code_filename = format!("fuzz_issues/compiler_timeouts/{}_min.cpp", min_hex_hash);
			
			std::fs::write(orig_code_filename, orig_code).expect("couldn't write to file?");
			std::fs::write(min_code_filename, min_code).expect("couldn't write to file?");
		}
		GenCodeResult::CompilerFailure(_,_,_) => {
			let min_hex_hash_full = get_hex_hash_of_bytes(min_code.as_bytes());
			let min_hex_hash = &min_hex_hash_full[0..10];
			let orig_code_filename = format!("fuzz_issues/compiler_fails/{}_orig.cpp", min_hex_hash);
			let min_code_filename = format!("fuzz_issues/compiler_fails/{}_min.cpp", min_hex_hash);
			
			std::fs::write(orig_code_filename, orig_code).expect("couldn't write to file?");
			std::fs::write(min_code_filename, min_code).expect("couldn't write to file?");
		}
		GenCodeResult::RuntimeDiff(input) => {
			let min_hex_hash_full = get_hex_hash_of_bytes(min_code.as_bytes());
			let min_hex_hash = &min_hex_hash_full[0..10];
			let orig_code_filename = format!("fuzz_issues/runtime_diffs/{}_orig.cpp", min_hex_hash);
			let min_code_filename = format!("fuzz_issues/runtime_diffs/{}_min.cpp", min_hex_hash);
			let input_filename = format!("fuzz_issues/runtime_diffs/{}_input.input", min_hex_hash);
			
			std::fs::write(orig_code_filename, orig_code).expect("couldn't write to file?");
			std::fs::write(min_code_filename, min_code).expect("couldn't write to file?");
			std::fs::write(input_filename, input).expect("couldn't write to file?");
		}
		_ => panic!("uuhhhh....implement this")
	}
}

fn generate_random_input_for_program(num_i_vals : usize, num_f_vals : usize, num_d_vals : usize) -> String {
	let mut rng = Rand::default();
	
	let mut input_string = String::with_capacity(1024);
	
	let mut i_vals = Vec::<i32>::with_capacity(num_i_vals);
	for _ in 0..num_i_vals { i_vals.push(rng.rand() as i32); }
	
	let mut f_vals = Vec::<f32>::with_capacity(num_f_vals);
	for _ in 0..num_f_vals { f_vals.push(rng.randf() * 2.0 - 1.0); }
	
	let mut d_vals = Vec::<f64>::with_capacity(num_d_vals);
	for _ in 0..num_d_vals { d_vals.push((rng.randf() * 2.0 - 1.0) as f64); }

	for i_val in i_vals { write!(&mut input_string, "{}\n", i_val).expect(""); }
	for f_val in f_vals { write!(&mut input_string, "{}\n", f_val).expect(""); }
	for d_val in d_vals { write!(&mut input_string, "{}\n", d_val).expect(""); }

	return input_string;
}

fn fuzz_simd_codegen_loop(type_to_intrinsics_map : &HashMap<X86SIMDType, Vec<X86SIMDIntrinsic>>, compilation_tests : &Vec<TestCompilation>, runtime_tests : &Vec<TestRuntime>, fuzz_mode : GenCodeFuzzMode, total_num_cases_done : Arc<AtomicUsize>) {
	loop {
		let mut codegen_ctx = X86SIMDCodegenCtx::default();
		generate_codegen_ctx(&mut codegen_ctx, &type_to_intrinsics_map);
		
		let (cpp_code, num_i_vals, num_f_vals, num_d_vals) = generate_cpp_code_from_codegen_ctx(&codegen_ctx);

		// Test compilation
		let res = test_generated_code_compilation(&cpp_code, compilation_tests);

		match res {
			GenCodeResult::CompilerTimeout => {
				print!("Got timeout, trying to minimize...\n");
				let min_ctx = minimize_gen_code(&codegen_ctx, &res, compilation_tests, &runtime_tests);
				save_out_failure_info(&codegen_ctx, &min_ctx, &res);
			}
			GenCodeResult::CompilerFailure(err_code,_,_) => {
				print!("Got compiler failure error code {}, trying to minimize...\n", err_code);
				let min_ctx = minimize_gen_code(&codegen_ctx, &res, compilation_tests, &runtime_tests);
				save_out_failure_info(&codegen_ctx, &min_ctx, &res);
			}
			GenCodeResult::RuntimeFailure(_,_) => { panic!("??") }
			GenCodeResult::RuntimeDiff(_) => { panic!("??") }
			GenCodeResult::Success => { /*Do nothing*/ }
		}
		
		if matches!(fuzz_mode, GenCodeFuzzMode::CrashAndDiff) {
			const NUM_INPUTS_PER_CODEGEN : i32 = 10;
			for _ in 0..NUM_INPUTS_PER_CODEGEN {
				let input = generate_random_input_for_program(num_i_vals, num_f_vals, num_d_vals);
				let res = test_generated_code_runtime(&runtime_tests, &input);
				
				match res {
					GenCodeResult::CompilerTimeout => { panic!("??") }
					GenCodeResult::CompilerFailure(_,_,_) => { panic!("??") }
					GenCodeResult::RuntimeFailure(err_code, _) => {
						print!("Got runtime failure error code {}. For now we ignore these\n", err_code);
						panic!("Maybe implement this?");
					}
					GenCodeResult::RuntimeDiff(_) => {
						print!("Got runtime difference, trying to minimize....\n");
						let min_ctx = minimize_gen_code(&codegen_ctx, &res, compilation_tests, &runtime_tests);
						save_out_failure_info(&codegen_ctx, &min_ctx, &res);
					}
					GenCodeResult::Success => { /*Do nothing*/ }
				}
			}
		}

		//print!("Finished one round of fuzzing.\n");
		total_num_cases_done.fetch_add(1, Ordering::SeqCst);
	}
}

fn fuzz_simd_codegen(config_filename : &str) {
	// Open the data xml file for the intrinsics
	let intrinsics_docs_filename = "data-3.6.0.xml";
	let contents = std::fs::read_to_string(intrinsics_docs_filename);
	
	if contents.is_err() {
		print!("Could not open intrinsics docs file '{}'. Maybe you need to download it?\n", intrinsics_docs_filename);
		return;
	}
	let contents = contents.unwrap();
	
	let config_contents = std::fs::read_to_string(config_filename);
	if config_contents.is_err() {
		print!("Could not open config file '{}'\n", config_filename);
		return;
	}
	let config_contents = config_contents.unwrap();
	
	let intrinsics_list = parse_intel_intrinsics_xml(&contents);

	let type_to_intrinsics_map = {
		let mut type_to_intrinsics_map = HashMap::<X86SIMDType, Vec<X86SIMDIntrinsic>>::new();
		
		for intrinsic in intrinsics_list {
			let intrinsics_for_type = type_to_intrinsics_map.entry(intrinsic.return_type)
				.or_insert_with(|| Vec::<X86SIMDIntrinsic>::with_capacity(4));
				
			intrinsics_for_type.push(intrinsic);
		}

		type_to_intrinsics_map
	};
	
	let (compilation_tests, fuzz_mode) = parse_compiler_config(&config_contents);

	let shared_type_to_intrinsics_map = Arc::new(type_to_intrinsics_map);


	let mut thread_handles = Vec::<std::thread::JoinHandle<_>>::new();

	const NUM_THREADS : u32 = 64;
	
	print!("Launching fuzzer with {} threads\n", NUM_THREADS);
	
	let num_cases_state = Arc::new(AtomicUsize::new(0));
	
	for thread_index in 0..NUM_THREADS {
		let mut compilation_tests = compilation_tests.clone();

		// Replace generic filenames with specific ones in the config
		for (ii, compilation_test) in compilation_tests.iter_mut().enumerate() {
			for compiler_arg in compilation_test.compiler_args.iter_mut() {
				// TODO: Replace substring, to support MSVC /Fe arg
				*compiler_arg = compiler_arg.replace("^GENERATED_SOURCE_FILENAME^", &format!("tmp/simd_gen_thr{}_test.cpp", thread_index));
				*compiler_arg = compiler_arg.replace("^GENERATED_EXE_FILENAME^", &format!("tmp/simd_gen_thr{}_test_{}.exe", thread_index, ii));
			}

			// TODO: Blegh, could be better
			compilation_test.code_filename = format!("tmp/simd_gen_thr{}_test.cpp", thread_index);
		}

		let mut runtime_tests = Vec::<TestRuntime>::with_capacity(compilation_tests.len());
		if matches!(fuzz_mode, GenCodeFuzzMode::CrashAndDiff) {
			// TODO: Less hacky way of doing this...esp. for threading
			for ii in 0..compilation_tests.len() {
				runtime_tests.push(TestRuntime {
					program_exe: format!("tmp/simd_gen_thr{}_test_{}.exe", thread_index, ii)
				});
			}
		}

		let shared_type_to_intrinsics_map = shared_type_to_intrinsics_map.clone();
		let fuzz_mode = fuzz_mode.clone();
		let num_cases_state = num_cases_state.clone();
		
		let thread_handle = std::thread::spawn(move || {
			fuzz_simd_codegen_loop(&shared_type_to_intrinsics_map, &compilation_tests, &runtime_tests, fuzz_mode, num_cases_state);
		});
		thread_handles.push(thread_handle);
	}
	
	print!("Done launching\n");
	
	let start_time = Instant::now();
	loop {
		std::thread::sleep(Duration::from_secs(1));
		let time_so_far = Instant::now().duration_since(start_time);
		let seconds_so_far = time_so_far.as_secs_f32();
		let num_cases_so_far = num_cases_state.load(Ordering::SeqCst);
		let avg_cases_per_second = num_cases_so_far as f32 / seconds_so_far;
		print!("{:10.1} sec uptime | {:10} cases | {:10.2} cps\n", seconds_so_far, num_cases_so_far, avg_cases_per_second);
	}
	
	// TODO: Uhhhh......yeah have some way of breaking out of the above loop  I guess? Ctrl-C?
	for thread_handle in thread_handles {
		thread_handle.join().expect("couldn't join one of the threads");
	}
}

fn print_usage() {
	print!("usage: [exe] fuzz [config_filename]\n");
}

fn main() {

	if std::env::args().count() < 2 {
		print_usage();
		return;
	}

	let method = std::env::args().nth(1).expect("no args?");
	if method == "fuzz" {
		let config_filename = std::env::args().nth(2).expect("missing config?");
		fuzz_simd_codegen(&config_filename);
	}
	else {
		print_usage();
		return;
	}

	// TODO: How to handle int divide-by-zero, and possibly other traps?
}
