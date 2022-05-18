// :/
#![allow(unused_parens)]

// Opt bait is kinda just commented out for now, but left some dead code in cause lazy
#![allow(dead_code)]

// Uh, yeah nightly only I think but c'mon this is good stuff
#![feature(portable_simd)]
#![feature(thread_id_value)]
#![feature(associated_type_defaults)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use std::arch::x86_64::{_rdtsc};

use sha2::{Sha256, Digest};

mod rand;

mod compilation_config;
use compilation_config::{test_generated_code_compilation, parse_compiler_config};
use compilation_config::{TestCompilation, GenCodeResult, GenCodeFuzzMode, CompilationConfig};

mod x86_parse_spec;
use x86_parse_spec::parse_intel_intrinsics_xml;

mod x86_intrinsics;
use x86_intrinsics::{X86SIMDIntrinsic, X86SIMDType};

mod parse_exe;

mod x86_codegen_ctx;
use x86_codegen_ctx::{X86SIMDCodegenCtx};

mod exec_mem;

mod codegen_fuzzing;
use codegen_fuzzing::CodegenFuzzer;

mod x86_codegen_fuzzing;
use x86_codegen_fuzzing::{X86CodegenFuzzer, X86CodegenFuzzerThreadInput, X86CodegenFuzzerCodeMetadata, X86CodeFuzzerInputValues, X86SIMDOutputValues };

mod arm_intrinsics;
use arm_intrinsics::{ARMSIMDType, ARMSIMDIntrinsic};

mod arm_parse_spec;
use arm_parse_spec::parse_arm_intrinsics_json;

mod arm_codegen_ctx;
use arm_codegen_ctx::ARMSIMDCodegenCtx;

mod arm_codegen_fuzzing;
use arm_codegen_fuzzing::{ARMCodegenFuzzer, ARMCodegenFuzzerThreadInput, ARMCodegenFuzzerCodeMetadata, ARMCodeFuzzerInputValues, ARMSIMDOutputValues};

mod code_exe_server_conn;

fn get_hex_hash_of_bytes(input : &[u8]) -> String {
	let mut hasher = Sha256::new();
	hasher.update(input);
	let digest = hasher.finalize();
	hex::encode(digest)
}

fn save_out_failure_info(orig_code : &str, min_code : &str, result : &GenCodeResult) {
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

fn fuzz_simd_codegen_loop<FuzzType,ThreadInput,CodegenCtx,CodeMeta,FuzzerInput,FuzzerOutput>(
		input : ThreadInput, compilation_tests : &Vec<TestCompilation>, fuzz_mode : GenCodeFuzzMode,
		total_num_cases_done : Arc<AtomicUsize>, total_bugs_found : Arc<AtomicUsize>, num_bytes_fuzzed : Arc<AtomicUsize>
	)
	where FuzzType : CodegenFuzzer<ThreadInput,CodegenCtx,CodeMeta,FuzzerInput,FuzzerOutput>, FuzzerOutput: Copy, CodegenCtx: Clone {
	
	let mut fuzzer = FuzzType::new_fuzzer_state(input);
	
	let num_inputs_per_codegen = fuzzer.num_inputs_per_codegen();
	
	loop {
		let codegen_ctx = fuzzer.generate_ctx();
		
		let (cpp_code, code_meta) = fuzzer.generate_cpp_code(&codegen_ctx);

		//println!("----------CODE-------------");
		//println!("{}", cpp_code);
		//println!("---------------------------");

		let res = test_generated_code_compilation(&cpp_code, compilation_tests);

		// TODO: UTF-8, bytes not necessarily same as chars, idk what rust gives but we only do ascii in this house so w/e
		let num_cpp_bytes = cpp_code.len();

		match res {
			GenCodeResult::CompilerTimeout => {
				todo!();
			}
			GenCodeResult::CompilerFailure(_err_code,_,_) => {
				let minim_checker = |this_fuzzer : &FuzzType, ctx: &CodegenCtx| {
					let (minim_cpp_code, _) = this_fuzzer.generate_cpp_code(ctx);
					let minim_res = test_generated_code_compilation(&minim_cpp_code, compilation_tests);
					return matches!(minim_res, GenCodeResult::CompilerFailure(_,_,_));
				};
				
				if let Some(min_ctx) = fuzzer.try_minimize(codegen_ctx, minim_checker) {
					let (min_cpp_code,_) = fuzzer.generate_cpp_code(&min_ctx);
					save_out_failure_info(&cpp_code, &min_cpp_code, &res);
				}
				else {
					println!("Could not minimize for whatever reason");
					save_out_failure_info(&cpp_code, &cpp_code, &res);
				}
				
				total_bugs_found.fetch_add(1, Ordering::SeqCst);
			}
			GenCodeResult::Success(ref compiled_outputs) => {
				if matches!(fuzz_mode, GenCodeFuzzMode::CrashAndDiff) {
					let mut bad_input : Option<FuzzerInput> = None;
					for _ in 0..num_inputs_per_codegen {
						let input = fuzzer.generate_random_input(&code_meta);

						let mut all_outputs_same = true;
						let mut first_output : Option<FuzzerOutput> = None;
						for compiled_out in compiled_outputs.iter(){
							let output = fuzzer.execute(&compiled_out.code_page, &code_meta, &input);
							if let Some(first_output) = first_output {
								if !fuzzer.are_outputs_the_same(&first_output, &output) {
									all_outputs_same = false;
									break;
								}
							}
							else {
								first_output = Some(output);
							}
						}
						
						if !all_outputs_same {
							bad_input = Some(input);
							break;
						}
					}
					
					if let Some(bad_input) = bad_input {
						let minim_checker = |this_fuzzer : &FuzzType, ctx: &CodegenCtx| {
							let (minim_cpp_code, minim_code_meta) = this_fuzzer.generate_cpp_code(ctx);
							let minim_res = test_generated_code_compilation(&minim_cpp_code, compilation_tests);
							if let GenCodeResult::Success(minim_compiled_outputs) = minim_res {

								// TODO: Code dup with above
								let mut all_outputs_same = true;
								let mut first_output : Option<FuzzerOutput> = None;
								for compiled_out in minim_compiled_outputs.iter(){
									let output = fuzzer.execute(&compiled_out.code_page, &minim_code_meta, &bad_input);
									if let Some(first_output) = first_output {
										if !fuzzer.are_outputs_the_same(&first_output, &output) {
											all_outputs_same = false;
											break;
										}
									}
									else {
										first_output = Some(output);
									}
								}
								
								return !all_outputs_same;
							}
							
							return false;
						};
						
						let input_str = fuzzer.save_input_to_string(&bad_input);
						if let Some(min_ctx) = fuzzer.try_minimize(codegen_ctx, minim_checker) {
							let (min_cpp_code,_) = fuzzer.generate_cpp_code(&min_ctx);
							save_out_failure_info(&cpp_code, &min_cpp_code, &GenCodeResult::RuntimeDiff(input_str));
						}
						else {
							println!("Could not minimize for whatever reason");
							save_out_failure_info(&cpp_code, &cpp_code, &GenCodeResult::RuntimeDiff(input_str));
						}
						
						total_bugs_found.fetch_add(1, Ordering::SeqCst);
					}
				}
			}
			_ => { panic!("bad possible return type from compilation") }
		};

		total_num_cases_done.fetch_add(1, Ordering::SeqCst);
		num_bytes_fuzzed.fetch_add(num_cpp_bytes, Ordering::SeqCst);
	}
}

fn fuzz_x86_simd_codegen(config_filename : &str, num_threads : u32) {
	// Open the data xml file for the intrinsics
	let intrinsics_docs_filename = "data-3-6-1.xml";
	let contents = std::fs::read_to_string(intrinsics_docs_filename);
	
	if contents.is_err() {
		print!("Could not open X86 intrinsics docs file '{}'. Maybe you need to download it?\n", intrinsics_docs_filename);
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
	
	let compilation_config = parse_compiler_config(&config_contents);
	let compilation_tests = compilation_config.compilations;
	let fuzz_mode = compilation_config.fuzz_mode;

	let mut thread_handles = Vec::<std::thread::JoinHandle<_>>::new();
	print!("Launching fuzzer with {} threads\n", num_threads);

	let num_cases_state = Arc::new(AtomicUsize::new(0));
	let num_bugs_found = Arc::new(AtomicUsize::new(0));
	let num_bytes_fuzzed = Arc::new(AtomicUsize::new(0));
	
	// This should ensure subsequent runs don't re-use the same seeds for everything
	let initial_time = unsafe { _rdtsc() };
	
	for thread_id in 0..num_threads {
		let compilation_tests = compilation_tests.clone();

		let own_type_to_intrinsics_map = type_to_intrinsics_map.clone();
		let fuzz_mode = fuzz_mode.clone();
		let num_cases_state = num_cases_state.clone();
		let num_bugs_found = num_bugs_found.clone();
		let num_bytes_fuzzed = num_bytes_fuzzed.clone();
		
		// Some prime numbers beause they're better, or so I hear
		let initial_seed = ((thread_id as u64) + 937) * 241 + initial_time;
		
		let thread_input = X86CodegenFuzzerThreadInput {
			thread_seed : initial_seed,
			type_to_intrinsics_map : own_type_to_intrinsics_map
		};
		
		let thread_handle = std::thread::spawn(move || {
			fuzz_simd_codegen_loop::<X86CodegenFuzzer, X86CodegenFuzzerThreadInput, X86SIMDCodegenCtx, X86CodegenFuzzerCodeMetadata, X86CodeFuzzerInputValues, X86SIMDOutputValues>(
				thread_input, &compilation_tests, fuzz_mode, num_cases_state, num_bugs_found, num_bytes_fuzzed);
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

		let num_bytes_so_far = num_bytes_fuzzed.load(Ordering::SeqCst);
		
		const BYTES_PER_KB : f64 = 1024.0;
		let avg_kb_per_sec = (num_bytes_so_far as f64) / (seconds_so_far as f64) / BYTES_PER_KB;

		print!("X86 | {:10.1} sec uptime | {:10} cases | {:10.2} cps | {:5} bugs | {:8.3} KB/s code fuzzed\n",
			seconds_so_far, num_cases_so_far, avg_cases_per_second, num_bugs_so_far, avg_kb_per_sec);
	}
}

fn fuzz_arm_simd_codegen(config_filename : &str, num_threads : u32) {
	let mut thread_handles = Vec::<std::thread::JoinHandle<_>>::new();
	print!("Launching fuzzer with {} threads\n", num_threads);

	let num_cases_state = Arc::new(AtomicUsize::new(0));
	let num_bugs_found = Arc::new(AtomicUsize::new(0));
	let num_bytes_fuzzed = Arc::new(AtomicUsize::new(0));
	
	let intrinsics_docs_filename = "arm_intrinsics.json";
	let contents = std::fs::read_to_string(intrinsics_docs_filename);
	
	if contents.is_err() {
		print!("Could not open ARM intrinsics docs file '{}'. Maybe you need to download it?\n", intrinsics_docs_filename);
		return;
	}
	
	let contents = contents.unwrap();

	let config_contents = std::fs::read_to_string(config_filename);
	if config_contents.is_err() {
		print!("Could not open config file '{}'\n", config_filename);
		return;
	}
	let config_contents = config_contents.unwrap();
	
	let compilation_config = parse_compiler_config(&config_contents);
	let compilation_tests = compilation_config.compilations;
	let fuzz_mode = compilation_config.fuzz_mode;
	
	let intrinsics_list = parse_arm_intrinsics_json(&contents, &compilation_config.mitigations);
	
	let type_to_intrinsics_map = {
		let mut type_to_intrinsics_map = HashMap::<ARMSIMDType, Vec<ARMSIMDIntrinsic>>::new();
		
		for intrinsic in intrinsics_list {
			let intrinsics_for_type = type_to_intrinsics_map.entry(intrinsic.return_type)
				.or_insert_with(|| Vec::<ARMSIMDIntrinsic>::with_capacity(4));
				
			intrinsics_for_type.push(intrinsic);
		}
	
		type_to_intrinsics_map
	};
	
	// This should ensure subsequent runs don't re-use the same seeds for everything
	let initial_time = unsafe { _rdtsc() };
	
	for thread_id in 0..num_threads {
		let num_cases_state = num_cases_state.clone();
		let num_bugs_found = num_bugs_found.clone();
		let num_bytes_fuzzed = num_bytes_fuzzed.clone();
		
		let compilation_tests = compilation_tests.clone();
		let type_to_intrinsics_map = type_to_intrinsics_map.clone();
		//let fuzz_mode = fuzz_mode.clone();
		
		// Some prime numbers beause they're better, or so I hear
		let initial_seed = ((thread_id as u64) + 937) * 241 + initial_time;
		
		let thread_handle = std::thread::spawn(move || {
			
			let thread_input = ARMCodegenFuzzerThreadInput {
				thread_seed : initial_seed,
				type_to_intrinsics_map : type_to_intrinsics_map,
				mode: fuzz_mode
			};
			
			fuzz_simd_codegen_loop::<ARMCodegenFuzzer, ARMCodegenFuzzerThreadInput, ARMSIMDCodegenCtx, ARMCodegenFuzzerCodeMetadata, ARMCodeFuzzerInputValues, ARMSIMDOutputValues>(
				thread_input, &compilation_tests, fuzz_mode, num_cases_state, num_bugs_found, num_bytes_fuzzed);
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
		let num_bytes_so_far = num_bytes_fuzzed.load(Ordering::SeqCst);
		
		const BYTES_PER_KB : f64 = 1024.0;
		let avg_kb_per_sec = (num_bytes_so_far as f64) / (seconds_so_far as f64) / BYTES_PER_KB;

		print!("ARM | {:10.1} sec uptime | {:10} cases | {:10.2} cps | {:5} bugs | {:8.3} KB/s code fuzzed\n",
			seconds_so_far, num_cases_so_far, avg_cases_per_second, num_bugs_so_far, avg_kb_per_sec);
	}
}

fn print_usage() {
	print!("usage: [exe] [fuzz-x86|fuzz-arm] [config_filename] [--threads NUM_THREADS]\n");
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
	if std::env::args().count() < 2 {
		print_usage();
		return;
	}
	
	let method = std::env::args().nth(1).expect("no args?");
	if method == "fuzz-x86" {
		let config_filename = std::env::args().nth(2).expect("missing config?");
		let num_threads = get_num_threads();
		fuzz_x86_simd_codegen(&config_filename, num_threads);
	}
	if method == "fuzz-arm" {
		let config_filename = std::env::args().nth(2).expect("missing config?");
		let num_threads = get_num_threads();
		fuzz_arm_simd_codegen(&config_filename, num_threads);
	}
	else {
		print_usage();
		return;
	}

	// TODO: How to handle int divide-by-zero, and possibly other traps?
}
