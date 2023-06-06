//! Runs build tasks, potentially in parallel.
//! Unaware of the build graph, pools, etc.; just command execution.
//!
//! TODO: consider rewriting to use poll() etc. instead of threads.
//! The threads might be relatively cheap(?) because they just block on
//! the subprocesses though?

use crate::depfile;
use crate::graph::{BuildId, RspFile};
use crate::scanner::Scanner;
use anyhow::{anyhow, bail};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::io::Write;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

#[cfg(unix)]
use std::sync::Mutex;

pub struct FinishedTask {
    /// A (faked) "thread id", used to put different finished builds in different
    /// tracks in a performance trace.
    pub tid: usize,
    pub buildid: BuildId,
    pub span: (Instant, Instant),
    pub result: TaskResult,
}

#[derive(PartialEq)]
pub enum Termination {
    Success,
    Interrupted,
    Failure,
}

/// The result of executing a build step.
pub struct TaskResult {
    pub termination: Termination,
    /// Console output.
    pub output: Vec<u8>,
    pub discovered_deps: Option<Vec<String>>,
}

/// Reads dependencies from a .d file path.
fn read_depfile(path: &str) -> anyhow::Result<Vec<String>> {
    let mut bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => bail!("read {}: {}", path, e),
    };
    let mut scanner = Scanner::new(&mut bytes);
    let parsed_deps = depfile::parse(&mut scanner)
        .map_err(|err| anyhow!(scanner.format_parse_error(path, err)))?;
    // TODO verify deps refers to correct output
    let deps: Vec<String> = parsed_deps
        .deps
        .iter()
        .map(|&dep| dep.to_string())
        .collect();
    Ok(deps)
}

fn write_rspfile(rspfile: &RspFile) -> anyhow::Result<()> {
    if let Some(parent) = rspfile.path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&rspfile.path, &rspfile.content)?;
    Ok(())
}

/// Executes a build task as a subprocess.
/// Returns an Err() if we failed outside of the process itself.
fn run_task(
    cmdline: &str,
    depfile: Option<&str>,
    rspfile: Option<&RspFile>,
) -> anyhow::Result<TaskResult> {
    if let Some(rspfile) = rspfile {
        write_rspfile(rspfile)?;
    }
    let mut result = run_command(cmdline)?;
    if result.termination == Termination::Success {
        if let Some(depfile) = depfile {
            result.discovered_deps = Some(read_depfile(depfile)?);
        }
    }
    Ok(result)
}

#[cfg(unix)]
lazy_static! {
    static ref TASK_MUTEX: Mutex<i32> = Mutex::new(0);
}

#[cfg(unix)]
fn run_command(cmdline: &str) -> anyhow::Result<TaskResult> {
    // Command::spawn() can leak FSs when run concurrently, see #14.
    let just_one = TASK_MUTEX.lock().unwrap();
    let p = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(cmdline)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    drop(just_one);

    let mut cmd = p.wait_with_output()?;
    let mut output = Vec::new();
    output.append(&mut cmd.stdout);
    output.append(&mut cmd.stderr);

    let mut termination = Termination::Success;
    if !cmd.status.success() {
        termination = Termination::Failure;
        if let Some(sig) = cmd.status.signal() {
            match sig {
                libc::SIGINT => {
                    write!(output, "interrupted").unwrap();
                    termination = Termination::Interrupted;
                }
                _ => write!(output, "signal {}", sig).unwrap(),
            }
        }
    }

    Ok(TaskResult {
        termination,
        output,
        discovered_deps: None,
    })
}

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

#[cfg(windows)]
struct Pipe {
    read: HANDLE,
    write: HANDLE,
}

#[cfg(windows)]
fn create_pipe(
    security_attribs: &windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
) -> anyhow::Result<Pipe> {
    use std::{io, mem};
    use windows_sys::Win32::System::Pipes::CreatePipe;

    let mut stdout_read = mem::MaybeUninit::uninit();
    let mut stdout_write = mem::MaybeUninit::uninit();
    let res = unsafe {
        CreatePipe(
            stdout_read.as_mut_ptr(),
            stdout_write.as_mut_ptr(),
            security_attribs,
            0,
        )
    };
    if res == 0 {
        bail!("CreatePipe failed: {}", io::Error::last_os_error());
    }

    Ok(Pipe {
        read: unsafe { stdout_read.assume_init() },
        write: unsafe { stdout_write.assume_init() },
    })
}

#[cfg(windows)]
fn run_command(cmdline: &str) -> anyhow::Result<TaskResult> {
    use std::{
        fs,
        io::{self, Read},
        iter, mem,
        os::windows::prelude::FromRawHandle,
        ptr,
    };
    use windows_sys::{
        w,
        Win32::{
            Foundation::{CloseHandle, GENERIC_READ, TRUE},
            Security::SECURITY_ATTRIBUTES,
            Storage::FileSystem::{
                CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            },
            System::Threading::{
                CreateProcessW, GetExitCodeProcess, WaitForSingleObject, INFINITE,
                STARTF_USESTDHANDLES, STARTUPINFOW,
            },
        },
    };

    // Don't want to run `cmd /c` since that limits cmd line length to 8192 bytes.
    // std::process::Command can't take a string and pass it through to CreateProcess unchanged,
    // so call that ourselves.

    let security_attribs = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as _,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: TRUE,
    };

    let stdout = create_pipe(&security_attribs)?;
    let stderr = create_pipe(&security_attribs)?;

    let null_file = unsafe {
        CreateFileW(
            w!("NUL"),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &security_attribs,
            OPEN_EXISTING,
            0,
            0,
        )
    };
    if null_file == 0 {
        bail!("CreateFileW failed: {}", io::Error::last_os_error());
    }

    let mut startup_info = unsafe { mem::zeroed::<STARTUPINFOW>() };
    startup_info.cb = mem::size_of_val(&startup_info) as u32;
    startup_info.hStdInput = null_file;
    startup_info.hStdError = stderr.write;
    startup_info.hStdOutput = stdout.write;
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    let mut process_info = mem::MaybeUninit::uninit();
    let mut cmdline_wide: Vec<_> = cmdline.encode_utf16().chain(iter::once(0)).collect();
    let create_process_res = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmdline_wide.as_mut_ptr(),
            &security_attribs,
            std::ptr::null(),
            TRUE,
            0,
            std::ptr::null(),
            std::ptr::null(),
            &mut startup_info,
            process_info.as_mut_ptr(),
        )
    };
    if create_process_res == 0 {
        bail!("CreateProcessW failed: {}", io::Error::last_os_error());
    }
    let process_info = unsafe { process_info.assume_init() };

    unsafe {
        CloseHandle(stdout.write);
        CloseHandle(stderr.write);
        CloseHandle(null_file);
    }

    let mut output = Vec::new();
    unsafe { fs::File::from_raw_handle(stdout.read as _) }.read_to_end(&mut output)?;
    unsafe { fs::File::from_raw_handle(stderr.read as _) }.read_to_end(&mut output)?;

    let mut exit_code: u32 = 0;
    unsafe {
        WaitForSingleObject(process_info.hProcess, INFINITE);
        GetExitCodeProcess(process_info.hProcess, &mut exit_code);
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }

    let termination = match exit_code {
        0 => Termination::Success,
        0xC000013A => Termination::Interrupted,
        _ => Termination::Failure,
    };

    Ok(TaskResult {
        termination,
        output,
        discovered_deps: None,
    })
}

/// Tracks faked "thread ids" -- integers assigned to build tasks to track
/// parallelism in perf trace output.
struct ThreadIds {
    /// An entry is true when claimed, false or nonexistent otherwise.
    slots: Vec<bool>,
}
impl ThreadIds {
    fn new() -> Self {
        ThreadIds { slots: Vec::new() }
    }

    fn claim(&mut self) -> usize {
        match self.slots.iter().position(|&used| !used) {
            Some(idx) => {
                self.slots[idx] = true;
                idx
            }
            None => {
                let idx = self.slots.len();
                self.slots.push(true);
                idx
            }
        }
    }

    fn release(&mut self, slot: usize) {
        self.slots[slot] = false;
    }
}

pub struct Runner {
    finished_send: mpsc::Sender<FinishedTask>,
    finished_recv: mpsc::Receiver<FinishedTask>,
    pub running: usize,
    tids: ThreadIds,
    parallelism: usize,
}

impl Runner {
    pub fn new(parallelism: usize) -> Self {
        let (tx, rx) = mpsc::channel();
        Runner {
            finished_send: tx,
            finished_recv: rx,
            running: 0,
            tids: ThreadIds::new(),
            parallelism,
        }
    }

    pub fn can_start_more(&self) -> bool {
        self.running < self.parallelism
    }

    pub fn is_running(&self) -> bool {
        self.running > 0
    }

    pub fn start(
        &mut self,
        id: BuildId,
        cmdline: String,
        depfile: Option<String>,
        rspfile: Option<RspFile>,
    ) {
        let tid = self.tids.claim();
        let tx = self.finished_send.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            let result =
                run_task(&cmdline, depfile.as_deref(), rspfile.as_ref()).unwrap_or_else(|err| {
                    TaskResult {
                        termination: Termination::Failure,
                        output: err.to_string().into_bytes(),
                        discovered_deps: None,
                    }
                });
            let finish = Instant::now();

            let task = FinishedTask {
                tid,
                buildid: id,
                span: (start, finish),
                result,
            };
            // The send will only fail if the receiver disappeared, e.g. due to shutting down.
            let _ = tx.send(task);
        });
        self.running += 1;
    }

    /// Wait for a build to complete, with a timeout.
    /// If the timeout elapses return None.
    pub fn wait(&mut self, dur: Duration) -> Option<FinishedTask> {
        let task = match self.finished_recv.recv_timeout(dur) {
            Err(mpsc::RecvTimeoutError::Timeout) => return None,
            // The unwrap() checks the recv() call, to panic on mpsc errors.
            r => r.unwrap(),
        };
        self.tids.release(task.tid);
        self.running -= 1;
        Some(task)
    }
}
