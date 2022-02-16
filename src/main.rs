// :/
#![allow(unused_parens)]

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
use codegen_ctx::{X86SIMDCodegenCtx, X86SIMDCodegenNode, X86SIMDOptBaitNode};
use codegen_ctx::{generate_cpp_code_from_codegen_ctx, generate_codegen_ctx};

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
		if matches!(res, GenCodeResult::Success(_)) {
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

fn offset_nodes_after_idx_in_ctx(ctx: &mut X86SIMDCodegenCtx, start_idx : usize, amount : isize) {
	// Clean up any references in nodes
	for ctx_node in &mut ctx.intrinsics_sequence {
		if let X86SIMDCodegenNode::Produced(ref mut intrinsic) = ctx_node {
			for ref_idx in intrinsic.references.iter_mut() {
				if *ref_idx >= start_idx {
					*ref_idx = (*ref_idx as isize + amount) as usize;
				}
			}
		}
		else if let X86SIMDCodegenNode::OptBait(ref mut opt_bait_node) = ctx_node {
			if opt_bait_node.node_idx >= start_idx {
				opt_bait_node.node_idx = (opt_bait_node.node_idx as isize + amount) as usize;
			}
		}
	}
	
	// Clean up any references in type_to_ref_idx
	for (_simd_type, ref_indices) in ctx.type_to_ref_idx.iter_mut() {
		for ref_idx in ref_indices.iter_mut() {
			if *ref_idx >= start_idx {
				*ref_idx = (*ref_idx as isize + amount) as usize;
			}
		}
	} 
}

fn add_opt_bait_profiling(orig_ctx : &X86SIMDCodegenCtx) -> (X86SIMDCodegenCtx, usize) {
	let mut rng = Rand::default();

	let mut var_idx = 0;
	for _ in 0..10 {
		let idx = (rng.rand_size() % (orig_ctx.intrinsics_sequence.len() - 1)) + 1;
		if let Some(node_idx) = orig_ctx.maybe_get_node_of_type(orig_ctx.get_return_type(), idx, 0) {
			var_idx = node_idx;
			break;
		}
	}

	let mut new_ctx = orig_ctx.clone();

	if var_idx != 0 {
		new_ctx.intrinsics_sequence.drain(0..var_idx);
		offset_nodes_after_idx_in_ctx(&mut new_ctx, 0, (var_idx as isize) * -1);
		//print!("profiling var not 0\n");
	}

	return (new_ctx, var_idx);
}

fn get_and_mask_for_value(var_val : &Vec<u8>, rng : &mut Rand) -> Vec<u8> {
	let mut mask = Vec::new();
	for byte in var_val {
		let mut mask_byte = 0;
		for bit in 0..8 {
			// If it's 1, we need to preserve it
			// If it's a 0, we have a 70% chance to force it to 0, or a 30% to pretend to preserve it
			if ((byte & (1 << bit)) != 0) || (rng.randf() < 0.3) {
				mask_byte |= (1 << bit);
			}
		}

		mask.push(mask_byte);
	}
	
	return mask;
}

fn get_or_mask_for_value(var_val : &Vec<u8>, rng : &mut Rand) -> Vec<u8> {
	let mut mask = Vec::new();
	for byte in var_val {
		let mut mask_byte = 0;
		for bit in 0..8 {
			// If it's 0, we need to preserve it
			// If it's a 1, we have a 70% chance to force it to 1, or a 30% to pretend to preserve it
			if ((byte & (1 << bit)) != 0) && (rng.randf() >= 0.3) {
				mask_byte |= (1 << bit);
			}
		}

		mask.push(mask_byte);
	}
	
	return mask;
}

fn get_opt_bait_node_for_var(var_type : &X86SIMDType, var_idx : usize, var_value : &Vec<u8>, rng : &mut Rand) -> X86SIMDCodegenNode {
	let do_and_intrinsic = rng.randf() > 0.5;

	let intrinsic_name = if matches!(var_type, X86SIMDType::M128i(_)) {
		if do_and_intrinsic { "_mm_and_si128" } else { "_mm_or_si128" }
	}
	else if matches!(var_type, X86SIMDType::M256i(_)) {
		if do_and_intrinsic { "_mm256_and_si256" } else { "_mm256_or_si256" }
	}
	else {
		panic!("Bad node type: right now only M128i and M256i");
	};
	
	let mask_val = if do_and_intrinsic {
		get_and_mask_for_value(var_value, rng)
	}
	else {
		get_or_mask_for_value(var_value, rng)
	};

	let fake_intrinsic = X86SIMDIntrinsic { intrinsic_name: intrinsic_name.to_string(), return_type: *var_type, param_types : Vec::<X86SIMDType>::new() };
	let opt_bait_node = X86SIMDOptBaitNode{ intrinsic : fake_intrinsic, node_idx: var_idx, mask: mask_val };
	return X86SIMDCodegenNode::OptBait(opt_bait_node);
}

fn add_opt_bait_with_values(orig_ctx : &X86SIMDCodegenCtx, var_idx : usize, var_value : &Vec<u8>) -> X86SIMDCodegenCtx {
	let mut new_ctx = orig_ctx.clone();

	let var_type = orig_ctx.get_type_of_node(var_idx);

	let mut rng = Rand::default();

	new_ctx.intrinsics_sequence.insert(var_idx, get_opt_bait_node_for_var(&var_type, var_idx, var_value, &mut rng));
	offset_nodes_after_idx_in_ctx(&mut new_ctx, var_idx, 1);

	if var_idx > 0 {
		let num_extra_baits = rng.rand() % 5;
		for ii in 0..num_extra_baits {
			let bait_index = rng.rand_size() % var_idx;
			new_ctx.intrinsics_sequence.insert(bait_index, get_opt_bait_node_for_var(&var_type, var_idx + 1 + ii as usize, var_value, &mut rng));
			offset_nodes_after_idx_in_ctx(&mut new_ctx, bait_index, 1);
		}
	}

	return new_ctx;
}

fn parse_profile_output(profile_output : &str) -> Vec<u8> {
	let mut bytes = Vec::new();
	for output_line in profile_output.split("\n") {
		let output_line = output_line.trim_start();
		let output_line = output_line.trim_end();
		//print!("Line '{}'\n", output_line);
		if output_line.len() > 0 {
			bytes.push(u8::from_str_radix(output_line, 16).unwrap());
		}
	}
	
	return bytes;
}

fn fuzz_simd_codegen_loop(type_to_intrinsics_map : &HashMap<X86SIMDType, Vec<X86SIMDIntrinsic>>, compilation_tests : &Vec<TestCompilation>, runtime_tests : &Vec<TestRuntime>, fuzz_mode : GenCodeFuzzMode, total_num_cases_done : Arc<AtomicUsize>) {
	//for _ in 0..500 {
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
				
				let mut is_actual_error = true;
				for _ in 0..3 {
					let new_res = test_generated_code_compilation(&cpp_code, compilation_tests);
					if !matches!(new_res, GenCodeResult::CompilerFailure(_,_,_)) {
						is_actual_error = false;
						break;
					}
				}
				
				if is_actual_error {
					let min_ctx = minimize_gen_code(&codegen_ctx, &res, compilation_tests, &runtime_tests);
					save_out_failure_info(&codegen_ctx, &min_ctx, &res);
				}
				else {
					print!("Actually, the error was just spurious, so let's skip it for now.\n");
				}
			}
			GenCodeResult::RuntimeFailure(_,_) => { panic!("??") }
			GenCodeResult::RuntimeDiff(_) => { panic!("??") }
			GenCodeResult::Success(_) => { /*Do nothing*/ }
		}
		
		if matches!(res, GenCodeResult::Success(_)) {
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
						GenCodeResult::Success(_) => { /*Do nothing*/ }
					}
				}
			}
			else if matches!(fuzz_mode, GenCodeFuzzMode::CrashAndOptBait) {
				let input = generate_random_input_for_program(num_i_vals, num_f_vals, num_d_vals);
				
				// TODO: For now only doing one test. In theory, we could loop over all and do the same thing for them,
				// though we don't care about diffs b/w the compiler settings, but with the original
				let mut compilation_tests_init = Vec::new();
				compilation_tests_init.push(compilation_tests[0].clone());
				
				let mut runtime_tests_init = Vec::new();
				runtime_tests_init.push(runtime_tests[0].clone());
				
				let init_res = test_generated_code_runtime(&runtime_tests_init, &input);
				
				let mut init_output = "".to_string();
				match init_res {
					GenCodeResult::RuntimeFailure(err_code, _) => { panic!("runtime failure huh?"); }
					GenCodeResult::Success(output) => { init_output = output; }
					_ => { panic!("shouldn't happen lol"); }
				}

				let (profile_ctx,profiled_var) = add_opt_bait_profiling(&codegen_ctx);
				
				let (profile_cpp_code, _, _, _) = generate_cpp_code_from_codegen_ctx(&profile_ctx);
				
				let profile_res = test_generated_code_compilation(&profile_cpp_code, &compilation_tests_init);
				
				if matches!(profile_res, GenCodeResult::Success(_)) {
					let profile_run_res = test_generated_code_runtime(&runtime_tests_init, &input);
					
					if let GenCodeResult::Success(profile_output) = profile_run_res {
						let var_bytes = parse_profile_output(&profile_output);
						
						// Inject "dead" code for that variable
						
						let injected_ctx = add_opt_bait_with_values(&codegen_ctx, profiled_var, &var_bytes);
						let (injected_cpp_code, _, _, _) = generate_cpp_code_from_codegen_ctx(&injected_ctx);
						let injected_res = test_generated_code_compilation(&injected_cpp_code, &compilation_tests_init);
						if matches!(injected_res, GenCodeResult::Success(_)) {
							let injected_runtime_res = test_generated_code_runtime(&runtime_tests_init, &input);
							
							if let GenCodeResult::Success(injected_output) = injected_runtime_res {
								if injected_output == init_output {
									//print!("All good, output of injected context matches what's expected\n");
								}
								else {
									print!("Uh oh...difference in injected output. We should save out the code etc.\n");
									let min_hex_hash_full = get_hex_hash_of_bytes(cpp_code.as_bytes());
									let min_hex_hash = &min_hex_hash_full[0..10];
									
									let orig_code_filename = format!("fuzz_issues/opt_bait/{}_orig.cpp", min_hex_hash);
									let bait_code_filename = format!("fuzz_issues/opt_bait/{}_bait.cpp", min_hex_hash);
									let input_filename = format!("fuzz_issues/opt_bait/{}_input.input", min_hex_hash);
									let orig_output_filename = format!("fuzz_issues/opt_bait/{}_orig.output", min_hex_hash);
									let bait_output_filename = format!("fuzz_issues/opt_bait/{}_bait.output", min_hex_hash);
									
									std::fs::write(orig_code_filename, cpp_code).expect("couldn't write to file?");
									std::fs::write(bait_code_filename, injected_cpp_code).expect("couldn't write to file?");
									std::fs::write(input_filename, input).expect("couldn't write to file?");
									std::fs::write(orig_output_filename, init_output).expect("couldn't write to file?");
									std::fs::write(bait_output_filename, injected_output).expect("couldn't write to file?");
								}
							}
							else {
								panic!("Injected context messed up at runtime");
							}
						}
						else {
							panic!("Injected context messed up at compile time");
						}
					}
					else {
						panic!("Profile context messed up at runtime");
					}
				}
				else {
					panic!("Profile context messed up at compilation");
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
	//print!("{:?}\n", compilation_tests);

	let shared_type_to_intrinsics_map = Arc::new(type_to_intrinsics_map);


	let mut thread_handles = Vec::<std::thread::JoinHandle<_>>::new();

	const NUM_THREADS : u32 = 20;
	
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
		if matches!(fuzz_mode, GenCodeFuzzMode::CrashAndDiff) || matches!(fuzz_mode, GenCodeFuzzMode::CrashAndOptBait) {
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
	//for thread_handle in thread_handles {
	//	thread_handle.join().expect("couldn't join one of the threads");
	//}
	//
	//print!("And, all thread loops exited, restarting fuzzer\n");
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
