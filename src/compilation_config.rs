

use std::process::{Command, Stdio};
use std::io::Write as IOWrite;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use std::sync::mpsc;

use crate::parse_exe::parse_obj_file;
use crate::exec_mem::ExecPage;

#[derive(Default, Debug, Clone)]
pub struct TestCompilation {
	pub compiler_exe : String,
	pub compiler_args : Vec<String>,
	pub timeout_seconds : i32,
	pub tmp_file_name : Option<String>,
	pub use_tmp_file : bool
}

//#[derive(Clone)]
pub struct CompiledCodeOutput {
	pub code_page : ExecPage
}

enum ProcessResult {
	Success(Vec<u8>),
	Error(i32, String, String),
	Timeout
}

pub enum GenCodeResult {
	Success(Vec<CompiledCodeOutput>), // stdout of program
	CompilerTimeout,
	CompilerFailure(i32, String, String),
	RuntimeDiff(String)
}

// This is basically saying "send this data to this stdin handle" for a compiler invocation
pub struct CompilerIOMessage_WriteStdin {
	stdin : std::process::ChildStdin,
	input : String
}

pub enum CompilerIOMessage {
	WriteStdin(CompilerIOMessage_WriteStdin),
	Exit
}

// This is meant to handle actually sending stdin to compilers that need it from a specific thread
// We don't want to do this synchronously while waiting for the compiler output to finish, since that can deadlock
// Previously, we just spawned a new thread each time we compiled something, but to avoid excess thread usage we're
// trying to use a single thread as much as possible
// TODO: Should we allow more than one IO thread, or does that not help perf?
pub struct CompilerIOThread {
	receiver : mpsc::Receiver<CompilerIOMessage>,
}

impl CompilerIOThread {
	pub fn spawn_io_thread() -> (CompilerIOThreadHandle, std::thread::JoinHandle<()>) {
		
		let (tx, rx) : (mpsc::Sender<CompilerIOMessage>, mpsc::Receiver<CompilerIOMessage>) = mpsc::channel();
		
		let io_thread = CompilerIOThread {
			receiver: rx
		};
		
		let join_handle = std::thread::spawn(move || {
			for msg in io_thread.receiver.iter() {
				match msg {
					CompilerIOMessage::WriteStdin(mut write_stdin) => {
						write_stdin.stdin.write_all(write_stdin.input.as_bytes()).expect("Failed to write to stdin");
					}
					CompilerIOMessage::Exit => {
						break;
					}
				}
			}
		});
		
		let io_thread_handle = CompilerIOThreadHandle::new(tx);
		
		return (io_thread_handle, join_handle);
	}
}

#[derive(Debug, Clone)]
pub struct CompilerIOThreadHandle {
	sender : mpsc::Sender<CompilerIOMessage>
}

impl CompilerIOThreadHandle {
	pub fn new(sender : mpsc::Sender<CompilerIOMessage>) -> Self {
		Self {
			sender: sender
		}
	}
	
	pub fn send(&self, msg : CompilerIOMessage) {
		self.sender.send(msg).expect("could not send msg to compiler IO thread");
	}
	
	pub fn kill_thread(&self) {
		self.sender.send(CompilerIOMessage::Exit).expect("could not send kill msg to compiler IO thread");
	}
}

// Returns the output of the process if successful, or the error code if not, or that it timed out
fn run_process_with_timeout(exe : &str, args : &Vec<String>, input : &str, timeout_seconds : Option<i32>, io_thread_handle : &CompilerIOThreadHandle) -> ProcessResult {
	//print!("Running process {:?} with args {:?}\n", exe, args);
	let mut child = Command::new(exe)
		.args(args)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("command failed to start");
	
	// Send the stdin to the IO thread: this is to ensure that we don't deadlock waiting for buffers to flush while we aren't reading stdout
	let stdin = child.stdin.take().expect("Failed to open stdin");
	let msg = CompilerIOMessage::WriteStdin(CompilerIOMessage_WriteStdin{
		stdin: stdin,
		input: input.to_string()
	});

	io_thread_handle.send(msg);
	
	let compile_start = Instant::now();
	loop {
		if let Some(timeout_seconds) = timeout_seconds {
			if Instant::now().duration_since(compile_start) > Duration::from_secs(timeout_seconds as u64) {
				print!("'{}' process timed out (if Windows maybe check we aren't leaking something?)\n", exe);
				let kill_res = child.kill();

				if kill_res.is_err() {
					print!("Got error when killing process {:?}\n", kill_res);
				}

				// Let's see if this helps...
				std::thread::sleep(Duration::from_millis(500));
				return ProcessResult::Timeout;
			}
		}

		match child.try_wait() {
			Ok(Some(_)) => { break; }
			Ok(None) => {
				std::thread::sleep(Duration::from_millis(100));
			}
			Err(e) => panic!("error attempting to wait: {}", e)
		}
	}

	// TODO: Timeouts....gahhhh....
	let output = child.wait_with_output().expect("could not read output of command");

	//join_handle.join().expect("The thread being joined has panicked");
	
	if output.status.success() {
		let proc_stdout = output.stdout;
		return ProcessResult::Success(proc_stdout);
	}
	else {
		let status_code = output.status.code().expect("failed to get exit code");
		//let proc_stdout = String::from_utf8_lossy(&output.stdout);
		let proc_stderr = String::from_utf8_lossy(&output.stderr);
		// TODO: stdout no longer printable since it's code output
		// stderr still good tho
		return ProcessResult::Error(status_code, "".to_string(), proc_stderr.to_string());
	}
}

pub fn test_generated_code_compilation(code : &str, compiles : &Vec<TestCompilation>, io_thread_handle : &CompilerIOThreadHandle) -> GenCodeResult {
	// TODO: better way?
	//std::fs::write(&compiles[0].code_filename, code).expect("couldn't write to file?");
	
	let mut generated_codes = Vec::<CompiledCodeOutput>::new();
	
	//println!("-------CODE-----------------");
	//println!("{}", code);
	//println!("----------------------------");
	
	for compile in compiles {
		let compile_result = run_process_with_timeout(&compile.compiler_exe, &compile.compiler_args, code, Some(compile.timeout_seconds), io_thread_handle);

		match compile_result {
			ProcessResult::Error(err_code, stdout, stderr) => {
				println!("COMPILER ERR: {}", stderr);
				return GenCodeResult::CompilerFailure(err_code, stdout, stderr);
			}
			ProcessResult::Timeout => {
				return GenCodeResult::CompilerTimeout;
			}
			ProcessResult::Success(proc_output) => {
				let code_page = if compile.use_tmp_file {
					let compiled_out = std::fs::read(compile.tmp_file_name.as_ref().unwrap()).unwrap();
					parse_obj_file(&compiled_out, "do_stuff").unwrap()
				}
				else {
					parse_obj_file(&proc_output, "do_stuff").unwrap()
				};
				generated_codes.push(CompiledCodeOutput { code_page: code_page });
			}
		}
	}

	return GenCodeResult::Success(generated_codes);
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GenCodeFuzzMode {
	CrashOnly,
	CrashAndDiff,
	CrashAndOptBait
}

fn parse_fuzz_mode(mode_str : &str) -> GenCodeFuzzMode {
	if mode_str == "crash+optbait" {
		return GenCodeFuzzMode::CrashAndOptBait;
	}
	else if mode_str == "crash+diff" {
		return GenCodeFuzzMode::CrashAndDiff;
	}
	else if mode_str == "crash" {
		return GenCodeFuzzMode::CrashOnly;
	}
	else {
		panic!("Could not understand testing mode '{}'", mode_str);
	}
}

pub struct CompilationConfig {
	pub compilations : Vec<TestCompilation>,
	pub fuzz_mode : GenCodeFuzzMode,
	pub mitigations : BTreeSet<String>,
	pub extra_config : serde_json::Value
}

// return struct at some point
pub fn parse_compiler_config(config : &str) -> CompilationConfig {
	let config_json : serde_json::Value = serde_json::from_str(config).expect("Could not parse JSON");
	
	let timeout = config_json["compilation_timeout_seconds"].as_i64().expect("could not parse compilation_timeout_seconds") as i32;
	
	let fuzz_mode_str = config_json["mode"].as_str().expect("could not parse mode");
	let fuzz_mode = parse_fuzz_mode(fuzz_mode_str);
	
	let mut test_compilations = Vec::<TestCompilation>::with_capacity(8);
	
	for compilation in config_json["compilations"].as_array().expect("compilations must be an array") {
		let compiler_exe = compilation["compiler_exe"].as_str().expect("Could not parse compiler_exe").to_string();
		let mut compiler_args = Vec::<String>::with_capacity(8);
		for compiler_arg in compilation["compiler_args"].as_array().expect("compiler_args must be an array") {
			compiler_args.push(compiler_arg.as_str().expect("compiler_args must contain strings").to_string());
		}
		
		let use_temp_file = compilation["use_temp_file"].as_bool().unwrap_or(false);
		
		test_compilations.push(TestCompilation {
			compiler_exe : compiler_exe,
			compiler_args :compiler_args,
			timeout_seconds : timeout,
			tmp_file_name: None, // will be filled in later...yeah could be better
			use_tmp_file: use_temp_file
		});
	}
	
	let mut mitigations = BTreeSet::<String>::new();
	if let Some(mitigations_json) = config_json["mitigations"].as_array() {
		for mitigation in mitigations_json {
			mitigations.insert(mitigation.as_str().expect("mitigations must contain strings").to_string());
		}
	}

	let extra_config = config_json["extra_config"].clone();

	return CompilationConfig {
		compilations: test_compilations,
		fuzz_mode: fuzz_mode,
		mitigations: mitigations,
		extra_config: extra_config
	};
}



