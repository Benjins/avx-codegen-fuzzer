// :/
#![allow(unused_parens)]

// Opt bait is kinda just commented out for now, but left some dead code in cause lazy
#![allow(dead_code)]

// Uh, yeah nightly only I think but c'mon this is good stuff
#![feature(portable_simd)]
#![feature(thread_id_value)]
#![feature(associated_type_defaults)]

use std::collections::HashMap;
//use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use std::arch::x86_64::{_rdtsc};

use sha2::{Sha256, Digest};

mod rand;

mod compilation_config;
use compilation_config::{test_generated_code_compilation, parse_compiler_config};
use compilation_config::{TestCompilation, GenCodeResult, GenCodeFuzzMode};

mod parse_spec;
use parse_spec::parse_intel_intrinsics_xml;

// Kinda just need everything here
mod intrinsics;
use intrinsics::*;

mod parse_exe;
//use parse_exe::{ExecPage, parse_obj_file};

mod codegen_ctx;
use codegen_ctx::{X86SIMDCodegenCtx};
use codegen_ctx::{generate_cpp_code_from_codegen_ctx};

mod exec_mem;

mod codegen_fuzzing;
use codegen_fuzzing::CodegenFuzzer;

mod x86_codegen_fuzzing;
use x86_codegen_fuzzing::{X86CodegenFuzzer, X86CodegenFuzzerThreadInput, X86CodegenFuzzerCodeMetadata, X86CodeFuzzerInputValues, X86SIMDOutputValues };

/*
fn check_minimized_gen_code(codegen_ctx : &X86SIMDCodegenCtx, expected_result : &GenCodeResult, compilation_tests : &Vec<TestCompilation>) -> bool {
	let (cpp_code, _, _, _) = generate_cpp_code_from_codegen_ctx(codegen_ctx);

	let mut input : Option<InputValues> = None;
	match expected_result {
		GenCodeResult::RuntimeFailure(expected_input, _) => {  input = Some(expected_input.clone()); }
		GenCodeResult::RuntimeDiff(expected_input) => {  input = Some(expected_input.clone()); }
		_ => { }
	}

	let res = test_generated_code_compilation(&cpp_code, compilation_tests);
	
	if let Some(input) = input {
		match(res) {
			GenCodeResult::Success(compiled_outputs) => {
				let res = test_generated_code_runtime(&compiled_outputs, &input, codegen_ctx.get_return_type());
				return std::mem::discriminant(&res) == std::mem::discriminant(expected_result);
			},
			_ => { }
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
pub fn minimize_gen_code(codegen_ctx : &X86SIMDCodegenCtx, expected_result : &GenCodeResult, compilation_tests : &Vec<TestCompilation>) -> X86SIMDCodegenCtx {
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
					if check_minimized_gen_code(&new_ctx, expected_result, compilation_tests) {
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
*/

fn get_hex_hash_of_bytes(input : &[u8]) -> String {
	let mut hasher = Sha256::new();
	hasher.update(input);
	let digest = hasher.finalize();
	hex::encode(digest)
}

fn save_out_failure_info(original_ctx : &X86SIMDCodegenCtx, min_ctx : &X86SIMDCodegenCtx, result : &GenCodeResult, seed : u64) {
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
			let seed_filename = format!("fuzz_issues/runtime_diffs/{}_seed.seed", min_hex_hash);
			
			std::fs::write(orig_code_filename, orig_code).expect("couldn't write to file?");
			std::fs::write(min_code_filename, min_code).expect("couldn't write to file?");
			std::fs::write(input_filename, input.write_to_str()).expect("couldn't write to file?");
			std::fs::write(seed_filename, format!("{}", seed)).expect("couldn't write to file?");
		}
		_ => panic!("uuhhhh....implement this")
	}
}

/*
fn generate_random_input_for_program(num_i_vals : usize, num_f_vals : usize, num_d_vals : usize) -> InputValues {
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

	return InputValues { i_vals: i_vals, f_vals: f_vals, d_vals: d_vals };
}

fn fuzz_simd_codegen_loop(initial_seed : u64, type_to_intrinsics_map : &HashMap<X86SIMDType, Vec<X86SIMDIntrinsic>>, compilation_tests : &Vec<TestCompilation>, fuzz_mode : GenCodeFuzzMode, total_num_cases_done : Arc<AtomicUsize>, total_bugs_found : Arc<AtomicUsize>, unique_seeds : Arc<Mutex<BTreeSet<u64>>>) {
	let mut outer_rng = Rand::new(initial_seed);

	loop {
		let round_seed = outer_rng.rand_u64();

		let mut codegen_ctx = X86SIMDCodegenCtx::new(round_seed);
		generate_codegen_ctx(&mut codegen_ctx, type_to_intrinsics_map);
		
		let (cpp_code, num_i_vals, num_f_vals, num_d_vals) = generate_cpp_code_from_codegen_ctx(&codegen_ctx);
		let res = test_generated_code_compilation(&cpp_code, compilation_tests);

		match res {
			GenCodeResult::CompilerTimeout => {
				print!("Got timeout, trying to minimize...\n");
				let min_ctx = minimize_gen_code(&codegen_ctx, &res, compilation_tests);
				save_out_failure_info(&codegen_ctx, &min_ctx, &res, round_seed);
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
					let min_ctx = minimize_gen_code(&codegen_ctx, &res, compilation_tests);
					save_out_failure_info(&codegen_ctx, &min_ctx, &res, round_seed);
				}
				else {
					print!("Actually, the error was just spurious, so let's skip it for now.\n");
				}
			}
			GenCodeResult::RuntimeFailure(_,_) => { panic!("??") }
			GenCodeResult::RuntimeDiff(_) => { panic!("??") }
			GenCodeResult::RuntimeSuccess => { panic!("???") }
			GenCodeResult::Success(compiled_outputs) => {
				//println!("Testing\n-----------------\n{}\n---------------", cpp_code);
				if matches!(fuzz_mode, GenCodeFuzzMode::CrashAndDiff) {
					const NUM_INPUTS_PER_CODEGEN : i32 = 1000;
					for _ in 0..NUM_INPUTS_PER_CODEGEN {
						let input = generate_random_input_for_program(num_i_vals, num_f_vals, num_d_vals);
						let res = test_generated_code_runtime(&compiled_outputs, &input, codegen_ctx.get_return_type());
						match res {
							GenCodeResult::CompilerTimeout => { panic!("??") }
							GenCodeResult::CompilerFailure(_,_,_) => { panic!("??") }
							GenCodeResult::RuntimeFailure(_, err_code) => {
								print!("Got runtime failure error code {}. For now we ignore these\n", err_code);
								panic!("Maybe implement this?");
							}
							GenCodeResult::RuntimeDiff(_) => {
								print!("Got runtime difference, trying to minimize....\n");
								let min_ctx = minimize_gen_code(&codegen_ctx, &res, compilation_tests);
								save_out_failure_info(&codegen_ctx, &min_ctx, &res, round_seed);
								total_bugs_found.fetch_add(1, Ordering::SeqCst);
							}
							GenCodeResult::Success(_) => { panic!("wait wrong one, that's compilation") },
							GenCodeResult::RuntimeSuccess => { /*Do nothing*/ }
						}
					}
				}
				else if matches!(fuzz_mode, GenCodeFuzzMode::CrashAndOptBait) {
					todo!();
				}
			}
		}

		//print!("Finished one round of fuzzing.\n");
		total_num_cases_done.fetch_add(1, Ordering::SeqCst);
		unique_seeds.lock().unwrap().insert(round_seed);
	}
}

fn fuzz_simd_codegen(config_filename : &str, num_threads : u32) {
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

	print!("Launching fuzzer with {} threads\n", num_threads);
	
	let num_cases_state = Arc::new(AtomicUsize::new(0));
	let num_bugs_found = Arc::new(AtomicUsize::new(0));
	let unique_seeds = Arc::new(Mutex::new(BTreeSet::<u64>::new()));
	
	// This should ensure subsequent runs don't re-use the same seeds for everything
	let initial_time = unsafe { _rdtsc() };
	
	for thread_id in 0..num_threads {
		let compilation_tests = compilation_tests.clone();

		let shared_type_to_intrinsics_map = shared_type_to_intrinsics_map.clone();
		let fuzz_mode = fuzz_mode.clone();
		let num_cases_state = num_cases_state.clone();
		let num_bugs_found = num_bugs_found.clone();
		let unique_seeds = unique_seeds.clone();
		
		// Some prime numbers beause they're better, or so I hear
		let initial_seed = ((thread_id as u64) + 937) * 241 + initial_time;
		
		let thread_handle = std::thread::spawn(move || {
			fuzz_simd_codegen_loop(initial_seed, &shared_type_to_intrinsics_map, &compilation_tests, fuzz_mode, num_cases_state, num_bugs_found, unique_seeds);
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
		let num_bugs_so_far = num_bugs_found.load(Ordering::SeqCst);
		
		let num_unique_seeds = unique_seeds.lock().unwrap().len();
		let unique_seed_ratio = (num_unique_seeds as f32) / (num_cases_so_far as f32);
		print!("{:10.1} sec uptime | {:10} cases | {:10.2} cps | {:5} bugs | {:10} unique seeds | {:5.4} seed uniqueness \n", seconds_so_far, num_cases_so_far, avg_cases_per_second, num_bugs_so_far, num_unique_seeds, unique_seed_ratio);
	}
	
	// TODO: Uhhhh......yeah have some way of breaking out of the above loop  I guess? Ctrl-C?
	//for thread_handle in thread_handles {
	//	thread_handle.join().expect("couldn't join one of the threads");
	//}
	//
	//print!("And, all thread loops exited, restarting fuzzer\n");
}
*/

fn fuzz_gen_simd_codegen_loop<FuzzType,ThreadInput,CodegenCtx,CodeMeta,FuzzerInput,FuzzerOutput>(
		input : ThreadInput, compilation_tests : &Vec<TestCompilation>, fuzz_mode : GenCodeFuzzMode, total_num_cases_done : Arc<AtomicUsize>, total_bugs_found : Arc<AtomicUsize>
	)
	where FuzzType : CodegenFuzzer<ThreadInput,CodegenCtx,CodeMeta,FuzzerInput,FuzzerOutput>, FuzzerOutput: std::marker::Copy {
	
	let mut fuzzer = FuzzType::new_fuzzer_state(input);
	
	loop {
		let codegen_ctx = fuzzer.generate_ctx();
		
		let (cpp_code, code_meta) = fuzzer.generate_cpp_code(&codegen_ctx);
		let res = test_generated_code_compilation(&cpp_code, compilation_tests);

		match res {
			GenCodeResult::CompilerTimeout => {
				todo!();
			}
			GenCodeResult::CompilerFailure(err_code,_,_) => {
				todo!();
			}
			GenCodeResult::RuntimeFailure(_,_) => { panic!("??") }
			GenCodeResult::RuntimeDiff(_) => { panic!("??") }
			GenCodeResult::RuntimeSuccess => { panic!("???") }
			GenCodeResult::Success(compiled_outputs) => {
				const NUM_INPUTS_PER_CODEGEN : i32 = 1000;
				for _ in 0..NUM_INPUTS_PER_CODEGEN {
					let input = fuzzer.generate_random_input(&code_meta);

					let mut first_output : Option<FuzzerOutput> = None;
					for compiled_out in compiled_outputs.iter(){
						let output = fuzzer.execute(&compiled_out.code_page, &code_meta, &input);
						if let Some(first_output) = first_output {
							if !fuzzer.are_outputs_the_same(&first_output, &output) {
								panic!("got two different results, TODO");
							}
						}
						else {
							first_output = Some(output);
						}
					}
				}
			}
		};

		total_num_cases_done.fetch_add(1, Ordering::SeqCst);
	}
}

fn fuzz_gen_x86_simd_codegen(config_filename : &str, num_threads : u32) {
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

	let mut thread_handles = Vec::<std::thread::JoinHandle<_>>::new();
	print!("Launching fuzzer with {} threads\n", num_threads);

	let num_cases_state = Arc::new(AtomicUsize::new(0));
	let num_bugs_found = Arc::new(AtomicUsize::new(0));
	
	// This should ensure subsequent runs don't re-use the same seeds for everything
	let initial_time = unsafe { _rdtsc() };
	
	for thread_id in 0..num_threads {
		let compilation_tests = compilation_tests.clone();

		let own_type_to_intrinsics_map = type_to_intrinsics_map.clone();
		let fuzz_mode = fuzz_mode.clone();
		let num_cases_state = num_cases_state.clone();
		let num_bugs_found = num_bugs_found.clone();
		
		// Some prime numbers beause they're better, or so I hear
		let initial_seed = ((thread_id as u64) + 937) * 241 + initial_time;
		
		let thread_input = X86CodegenFuzzerThreadInput {
			thread_seed : initial_seed,
			type_to_intrinsics_map : own_type_to_intrinsics_map
		};
		
		let thread_handle = std::thread::spawn(move || {
			fuzz_gen_simd_codegen_loop::<X86CodegenFuzzer, X86CodegenFuzzerThreadInput, X86SIMDCodegenCtx, X86CodegenFuzzerCodeMetadata, X86CodeFuzzerInputValues, X86SIMDOutputValues>(
				thread_input, &compilation_tests, fuzz_mode, num_cases_state, num_bugs_found);
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
		let num_bugs_so_far = num_bugs_found.load(Ordering::SeqCst);

		print!("{:10.1} sec uptime | {:10} cases | {:10.2} cps | {:5} bugs \n",
			seconds_so_far, num_cases_so_far, avg_cases_per_second, num_bugs_so_far);
	}
}

fn print_usage() {
	print!("usage: [exe] fuzz [config_filename]\n");
}

fn get_num_threads() -> u32 {
	for (ii,arg) in std::env::args().enumerate() {
		if arg == "--threads" {
			if ii == std::env::args().len() - 1 {
				panic!("--threads was the last argument");
			}
			else {
				let thread_count_arg = std::env::args().nth(ii + 1).expect("");
				let maybe_thread_count = thread_count_arg.parse::<u32>();
				if let Ok(thread_count) = maybe_thread_count {
					return thread_count;
				}
				else {
					panic!("--threads was not followed by a number");
				}
			}
		}
	}

	// Yeah, a good default. It's definitely not me being too lazy to add 'num_cpus = "1.13.1"' to my Cargo.toml file,
	// I'd much rather write out this comment explaining my poor decisions ha ha ha
	return 4;
}

fn main() {

	//test_thing();
	//return;

	if std::env::args().count() < 2 {
		print_usage();
		return;
	}
	
	let method = std::env::args().nth(1).expect("no args?");
	if method == "fuzz" {
		let config_filename = std::env::args().nth(2).expect("missing config?");
		let num_threads = get_num_threads();
		//fuzz_simd_codegen(&config_filename, num_threads);
		fuzz_gen_x86_simd_codegen(&config_filename, num_threads);
	}
	else {
		print_usage();
		return;
	}

	// TODO: How to handle int divide-by-zero, and possibly other traps?
}
