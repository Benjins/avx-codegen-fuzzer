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
use compilation_config::{TestCompilation, GenCodeResult, GenCodeFuzzMode};

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

mod loop_codegen_fuzzing;
use loop_codegen_fuzzing::{LoopFuzzerThreadInput, LoopCodegenCtx, LoopFuzzerCodeMetadata, LoopFuzzerInputValues, LoopFuzzerOutputValues, LoopFuzzer};

mod inline_asm_codegen_fuzzing;
use inline_asm_codegen_fuzzing::{AsmFuzzerThreadInput, AsmCodegenCtx, AsmFuzzerCodeMetadata, AsmFuzzerInputValues, AsmFuzzerOutputValues, AsmFuzzer};

fn get_hex_hash_of_bytes(input : &[u8]) -> String {
	let mut hasher = Sha256::new();
	hasher.update(input);
	let digest = hasher.finalize();
	hex::encode(digest)
}

fn save_out_failure_info(orig_code : &str, min_code : &str, result : &GenCodeResult, metadata : &str) {
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
			let min_meta_filename = format!("fuzz_issues/runtime_diffs/{}_min_meta.meta", min_hex_hash);
			
			std::fs::write(orig_code_filename, orig_code).expect("couldn't write to file?");
			std::fs::write(min_code_filename, min_code).expect("couldn't write to file?");
			std::fs::write(input_filename, input).expect("couldn't write to file?");
			std::fs::write(min_meta_filename, metadata).expect("couldn't write to file?");
		}
		_ => panic!("uuhhhh....implement this")
	}
}

fn fuzz_simd_codegen_loop<FuzzType,ThreadInput,CodegenCtx,CodeMeta,FuzzerInput,FuzzerOutput>(
		input : ThreadInput, compilation_tests : &Vec<TestCompilation>, fuzz_mode : GenCodeFuzzMode,
		total_num_cases_done : Arc<AtomicUsize>, total_bugs_found : Arc<AtomicUsize>, num_bytes_fuzzed : Arc<AtomicUsize>
	)
	where FuzzType : CodegenFuzzer<ThreadInput,CodegenCtx,CodeMeta,FuzzerInput,FuzzerOutput>, FuzzerOutput: Clone + std::fmt::Debug, CodegenCtx: Clone {
	
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
					let (min_cpp_code,min_code_meta) = fuzzer.generate_cpp_code(&min_ctx);
					let min_code_meta = fuzzer.save_meta_to_string(&min_code_meta);
					save_out_failure_info(&cpp_code, &min_cpp_code, &res, &min_code_meta);
				}
				else {
					println!("Could not minimize for whatever reason");
					let code_meta = fuzzer.save_meta_to_string(&code_meta);
					save_out_failure_info(&cpp_code, &cpp_code, &res, &code_meta);
				}
				
				total_bugs_found.fetch_add(1, Ordering::SeqCst);
			}
			GenCodeResult::Success(ref compiled_outputs) => {
				if matches!(fuzz_mode, GenCodeFuzzMode::CrashAndDiff) {
					let mut bad_input : Option<FuzzerInput> = None;
					for _ in 0..num_inputs_per_codegen {
						let input = fuzzer.generate_random_input(&code_meta);

						// TODO: Code dup
						let mut all_outputs_same = true;
						let mut first_output : Option<FuzzerOutput> = None;
						for compiled_out in compiled_outputs.iter(){
							let output = fuzzer.execute(&compiled_out.code_page, &code_meta, &input);
							if let Some(ref first_output) = first_output {
								if !fuzzer.are_outputs_the_same(first_output, &output) {
									//println!("OUTPUT DIFF:");
									//println!("O1: {:?}", first_output);
									//println!("O2: {:?}", output);
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
									if let Some(ref first_output) = first_output {
										if !fuzzer.are_outputs_the_same(first_output, &output) {
											//println!("OUTPUT DIFF:");
											//println!("O1: {:?}", first_output);
											//println!("O2: {:?}", output);
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
							save_out_failure_info(&cpp_code, &min_cpp_code, &GenCodeResult::RuntimeDiff(input_str), ""); // TODO
						}
						else {
							println!("Could not minimize for whatever reason");
							save_out_failure_info(&cpp_code, &cpp_code, &GenCodeResult::RuntimeDiff(input_str), ""); // TODO
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
		let mut compilation_tests = compilation_tests.clone();
		
		for compilation_test in compilation_tests.iter_mut() {
			if compilation_test.use_tmp_file {
				let tmp_filename = format!("tmp/x86_tmp_thr{}.o", thread_id);
				for arg in compilation_test.compiler_args.iter_mut() {
					*arg = arg.replace("^TMP_FILENAME^", &tmp_filename);
				}
				compilation_test.tmp_file_name = Some(tmp_filename);
			}
		}

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

fn repro_arm_simd_codegen(config_filename : &str, repro_filename : &str, meta_filename : &str, input_filename : &str) {
	println!("Reproing ARM simd on file {}", repro_filename);
	
	let config_contents = std::fs::read_to_string(config_filename);
	if config_contents.is_err() {
		print!("Could not open config file '{}'\n", config_filename);
		return;
	}
	let config_contents = config_contents.unwrap();
	
	let repro_code = std::fs::read_to_string(repro_filename).expect("could not read repro code file");
	let serial_meta = std::fs::read_to_string(meta_filename).expect("could not read code meta file");
	let input_txt = std::fs::read_to_string(input_filename).expect("could not read code meta file");

	let compilation_config = parse_compiler_config(&config_contents);
	
	let mut compilation_tests = compilation_config.compilations;
	let fuzz_mode = compilation_config.fuzz_mode;

	println!("~~~~~~~~~");
	println!("{:?}", compilation_tests);
	println!("~~~~~~~~~");
	for compilation_test in compilation_tests.iter_mut() {
		if compilation_test.use_tmp_file {
			let tmp_filename = "tmp/x86_tmp_thr_repro.o";
			for arg in compilation_test.compiler_args.iter_mut() {
				*arg = arg.replace("^TMP_FILENAME^", tmp_filename);
			}
			compilation_test.tmp_file_name = Some(tmp_filename.to_string());
		}
	}

	let mut exe_server_connect_addr : String = "".to_string();
	if let Some(extra_config) = compilation_config.extra_config.as_object() {
		if let Some(connect_addr) = extra_config["exe_server"].as_str() {
			exe_server_connect_addr = connect_addr.to_string();
		}
	}

	let repro_input = ARMCodegenFuzzerThreadInput {
		thread_seed : 0,
		type_to_intrinsics_map : HashMap::<ARMSIMDType, Vec<ARMSIMDIntrinsic>>::new(),
		mode: fuzz_mode,
		connect_addr: exe_server_connect_addr
	};
	
	let fuzzer = ARMCodegenFuzzer::new_fuzzer_state(repro_input);
	
	let res = test_generated_code_compilation(&repro_code, &compilation_tests);

	match res {
		GenCodeResult::Success(ref compiled_outputs) => {
			let code_meta = fuzzer.read_meta_from_string(&serial_meta);
			let input = fuzzer.read_input_from_string(&input_txt);

			println!("input len is {}", input.i_vals.len());

			let mut all_outputs_same = true;
			let mut first_output : Option<ARMSIMDOutputValues> = None;
			for compiled_out in compiled_outputs.iter(){
				let output = fuzzer.execute(&compiled_out.code_page, &code_meta, &input);
				if let Some(ref first_output) = first_output {
					if !fuzzer.are_outputs_the_same(first_output, &output) {
						println!("output1 = {:?}", first_output);
						println!("output2 = {:?}", output);
						all_outputs_same = false;
						break;
					}
				}
				else {
					first_output = Some(output);
				}
			}
			
			if all_outputs_same {
				println!("ALL SAME: {:?}", first_output.unwrap());
				std::process::exit(1);
			}
			else {
				println!("Succeeded in repro'ing the issue...different results on outputs");
				std::process::exit(0);
			}
		}
		_ => {
			println!("did not succeed in compiling repro case...is that expected?");
			std::process::exit(1);
		}
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
	
	let mut exe_server_connect_addr : String = "".to_string();
	if let Some(extra_config) = compilation_config.extra_config.as_object() {
		if let Some(connect_addr) = extra_config["exe_server"].as_str() {
			exe_server_connect_addr = connect_addr.to_string();
		}
	}
	
	// This should ensure subsequent runs don't re-use the same seeds for everything
	let initial_time = unsafe { _rdtsc() };
	
	for thread_id in 0..num_threads {
		let num_cases_state = num_cases_state.clone();
		let num_bugs_found = num_bugs_found.clone();
		let num_bytes_fuzzed = num_bytes_fuzzed.clone();
		
		let compilation_tests = compilation_tests.clone();
		let type_to_intrinsics_map = type_to_intrinsics_map.clone();
		let exe_server_connect_addr = exe_server_connect_addr.clone();
		
		// Some prime numbers beause they're better, or so I hear
		let initial_seed = ((thread_id as u64) + 937) * 241 + initial_time;
		
		let thread_handle = std::thread::spawn(move || {
			
			let thread_input = ARMCodegenFuzzerThreadInput {
				thread_seed : initial_seed,
				type_to_intrinsics_map : type_to_intrinsics_map,
				mode: fuzz_mode,
				connect_addr: exe_server_connect_addr
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

fn fuzz_loop_codegen(config_filename : &str, num_threads : u32) {
	let mut thread_handles = Vec::<std::thread::JoinHandle<_>>::new();
	print!("Launching fuzzer with {} threads\n", num_threads);

	let num_cases_state = Arc::new(AtomicUsize::new(0));
	let num_bugs_found = Arc::new(AtomicUsize::new(0));
	let num_bytes_fuzzed = Arc::new(AtomicUsize::new(0));

	let config_contents = std::fs::read_to_string(config_filename);
	if config_contents.is_err() {
		print!("Could not open config file '{}'\n", config_filename);
		return;
	}
	let config_contents = config_contents.unwrap();
	
	let compilation_config = parse_compiler_config(&config_contents);
	let compilation_tests = compilation_config.compilations;
	let fuzz_mode = compilation_config.fuzz_mode;
	
	let initial_time = unsafe { _rdtsc() };
	
	for thread_id in 0..num_threads {
		let num_cases_state = num_cases_state.clone();
		let num_bugs_found = num_bugs_found.clone();
		let num_bytes_fuzzed = num_bytes_fuzzed.clone();
		let compilation_tests = compilation_tests.clone();

		// Some prime numbers beause they're better, or so I hear
		let initial_seed = ((thread_id as u64) + 937) * 241 + initial_time;
		
		let thread_handle = std::thread::spawn(move || {
			
			let thread_input = LoopFuzzerThreadInput {
				thread_seed : initial_seed
			};
			
			fuzz_simd_codegen_loop::<LoopFuzzer, LoopFuzzerThreadInput, LoopCodegenCtx, LoopFuzzerCodeMetadata, LoopFuzzerInputValues, LoopFuzzerOutputValues>(
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

		print!("LOOP | {:10.1} sec uptime | {:10} cases | {:10.2} cps | {:5} bugs | {:8.3} KB/s code fuzzed\n",
			seconds_so_far, num_cases_so_far, avg_cases_per_second, num_bugs_so_far, avg_kb_per_sec);
	}
}

fn fuzz_asm_codegen(config_filename : &str, num_threads : u32) {
	print!("Launching fuzzer with {} threads\n", num_threads);

	let num_cases_state = Arc::new(AtomicUsize::new(0));
	let num_bugs_found = Arc::new(AtomicUsize::new(0));
	let num_bytes_fuzzed = Arc::new(AtomicUsize::new(0));

	let config_contents = std::fs::read_to_string(config_filename);
	if config_contents.is_err() {
		print!("Could not open config file '{}'\n", config_filename);
		return;
	}
	let config_contents = config_contents.unwrap();
	
	let compilation_config = parse_compiler_config(&config_contents);
	let compilation_tests = compilation_config.compilations;
	let fuzz_mode = compilation_config.fuzz_mode;
	
	let initial_time = unsafe { _rdtsc() };
	
	let mut thread_handles = Vec::<std::thread::JoinHandle<_>>::new();
	for thread_id in 0..num_threads {
		let num_cases_state = num_cases_state.clone();
		let num_bugs_found = num_bugs_found.clone();
		let num_bytes_fuzzed = num_bytes_fuzzed.clone();
		let compilation_tests = compilation_tests.clone();

		// Some prime numbers beause they're better, or so I hear
		let initial_seed = ((thread_id as u64) + 937) * 241 + initial_time;
		
		let thread_handle = std::thread::spawn(move || {
			
			let thread_input = AsmFuzzerThreadInput {
				thread_seed : initial_seed
			};
			
			fuzz_simd_codegen_loop::<AsmFuzzer, AsmFuzzerThreadInput, AsmCodegenCtx, AsmFuzzerCodeMetadata, AsmFuzzerInputValues, AsmFuzzerOutputValues>(
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

		print!("ASM | {:10.1} sec uptime | {:10} cases | {:10.2} cps | {:5} bugs | {:8.3} KB/s code fuzzed\n",
			seconds_so_far, num_cases_so_far, avg_cases_per_second, num_bugs_so_far, avg_kb_per_sec);
	}
}

fn print_usage() {
	print!("usage: [exe] [fuzz-x86|fuzz-arm|fuzz-loop|fuzz-asm] [config_filename] [--threads NUM_THREADS]\n");
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
	else if method == "fuzz-arm" {
		let config_filename = std::env::args().nth(2).expect("missing config?");
		let num_threads = get_num_threads();
		fuzz_arm_simd_codegen(&config_filename, num_threads);
	}
	else if method == "repro-arm" {
		let config_filename = std::env::args().nth(2).expect("missing config?");
		let repro_filename = std::env::args().nth(3).expect("missing repro filename?");
		let meta_filename = std::env::args().nth(4).expect("missing meta filename?");
		let input_filename = std::env::args().nth(5).expect("missing input filename?");
		repro_arm_simd_codegen(&config_filename, &repro_filename, &meta_filename, &input_filename);
	}
	else if method == "fuzz-loop" {
		let config_filename = std::env::args().nth(2).expect("missing config?");
		let num_threads = get_num_threads();
		fuzz_loop_codegen(&config_filename, num_threads);
	}
	else if method == "fuzz-asm" {
		let config_filename = std::env::args().nth(2).expect("missing config?");
		let num_threads = get_num_threads();
		fuzz_asm_codegen(&config_filename, num_threads);
	}
	else {
		print_usage();
		return;
	}

	// TODO: How to handle int divide-by-zero, and possibly other traps?
}
