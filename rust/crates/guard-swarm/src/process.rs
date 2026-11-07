//! Own the child and its tree. A browser-supplied PID never reaches this module.
use std::io::{self, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;

pub(crate) enum Output {
    Line(Vec<u8>),
    Diagnostic(String),
    End,
    Overflow,
}
pub(crate) struct Process {
    child: Child,
    #[cfg(windows)]
    tree: guard_runtime_windows_process::ChildTree,
    pub output: Receiver<Output>,
    reaped: bool,
    cancelled: Arc<AtomicBool>,
    io_workers: Vec<JoinHandle<()>>,
    #[cfg(target_os = "macos")]
    exit: MacExit,
}

impl Process {
    pub fn spawn(command: &mut Command, prompt: String) -> io::Result<Self> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(guard_runtime_windows_process::CHILD_TREE_CREATION_FLAGS);
        }
        let mut child = command.spawn()?;
        #[cfg(target_os = "macos")]
        let exit = match MacExit::new(child.id()) {
            Ok(exit) => exit,
            Err(error) => {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(child.id() as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        #[cfg(windows)]
        let tree = match guard_runtime_windows_process::ChildTree::adopt_suspended(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let (tx, output) = mpsc::sync_channel(128);
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut process = Self {
            child,
            #[cfg(windows)]
            tree,
            output,
            reaped: false,
            cancelled,
            io_workers: Vec::new(),
            #[cfg(target_os = "macos")]
            exit,
        };
        let stdout = process
            .child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing stdout"))?;
        let stderr = process
            .child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("missing stderr"))?;
        let mut stdin = process
            .child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing stdin"))?;
        #[cfg(unix)]
        {
            nonblocking(&stdout)?;
            nonblocking(&stderr)?;
            nonblocking(&stdin)?;
        }
        process
            .io_workers
            .push(pump(stdout, tx.clone(), false, process.cancelled.clone())?);
        process
            .io_workers
            .push(pump(stderr, tx.clone(), true, process.cancelled.clone())?);
        let cancelled = process.cancelled.clone();
        process.io_workers.push(
            std::thread::Builder::new()
                .name("swarm-input".into())
                .spawn(move || {
                    let mut rest = prompt.as_bytes();
                    while !rest.is_empty() && !cancelled.load(Ordering::Acquire) {
                        match stdin.write(rest) {
                            Ok(0) => break,
                            Ok(n) => rest = &rest[n..],
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(std::time::Duration::from_millis(20))
                            }
                            Err(_) => {
                                let _ = send(
                                    &tx,
                                    Output::Diagnostic(
                                        "Could not send the task to the CLI.".into(),
                                    ),
                                    &cancelled,
                                );
                                break;
                            }
                        }
                    }
                })?,
        );
        Ok(process)
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn finished(&mut self) -> io::Result<Option<bool>> {
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
            let status = waitid(
                Id::Pid(nix::unistd::Pid::from_raw(self.child.id() as i32)),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
            )
            .map_err(io::Error::from)?;
            if status == WaitStatus::StillAlive {
                return Ok(None);
            }
            // The leader is still ours and unreaped, so its process-group ID
            // cannot have been reused. Clean up descendants before reaping.
            self.kill_tree();
            let status = self.child.wait()?;
            self.reaped = true;
            Ok(Some(status.success()))
        }
        #[cfg(target_os = "macos")]
        {
            if !self.exit.finished()? {
                return Ok(None);
            }
            self.kill_tree();
            let status = self.child.wait()?;
            self.reaped = true;
            Ok(Some(status.success()))
        }
        #[cfg(windows)]
        {
            let status = self.child.try_wait()?;
            if status.is_some() {
                self.kill_tree();
                self.reaped = true;
            }
            Ok(status.map(|s| s.success()))
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.child.try_wait().map(|s| s.map(|s| s.success()))
        }
    }

    fn kill_tree(&self) {
        #[cfg(unix)]
        {
            if self.child.id() > 1 {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(self.child.id() as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        #[cfg(windows)]
        let _ = self.tree.terminate();
    }
}

// kqueue supplies a non-reaping exit observation on macOS, where nix does
// not expose waitid(WNOWAIT). The owned child reserves its PID until wait().
#[cfg(target_os = "macos")]
struct MacExit {
    queue: nix::sys::event::Kqueue,
    event: nix::sys::event::KEvent,
    exited: bool,
}
#[cfg(target_os = "macos")]
impl MacExit {
    fn new(pid: u32) -> io::Result<Self> {
        use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
        let queue = Kqueue::new()?;
        let event = KEvent::new(
            pid as usize,
            EventFilter::EVFILT_PROC,
            EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
            FilterFlag::NOTE_EXIT,
            0,
            0,
        );
        let exited = match queue.kevent(
            &[event],
            &mut [],
            Some(nix::libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        ) {
            Ok(_) => false,
            Err(nix::errno::Errno::ESRCH) => true,
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            queue,
            event,
            exited,
        })
    }
    fn finished(&mut self) -> io::Result<bool> {
        if !self.exited {
            let mut events = [self.event];
            self.exited = self.queue.kevent(
                &[],
                &mut events,
                Some(nix::libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )? > 0;
        }
        Ok(self.exited)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if !self.reaped {
            self.kill_tree();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        for worker in self.io_workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[cfg(unix)]
fn nonblocking(pipe: &impl std::os::fd::AsFd) -> io::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    let flags = OFlag::from_bits_truncate(fcntl(pipe, FcntlArg::F_GETFL)?);
    fcntl(pipe, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

fn send(tx: &SyncSender<Output>, mut output: Output, cancelled: &AtomicBool) -> bool {
    while !cancelled.load(Ordering::Acquire) {
        match tx.try_send(output) {
            Ok(()) => return true,
            Err(mpsc::TrySendError::Disconnected(_)) => return false,
            Err(mpsc::TrySendError::Full(value)) => output = value,
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

fn pump(
    mut reader: impl Read + Send + 'static,
    tx: SyncSender<Output>,
    diagnostic: bool,
    cancelled: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("swarm-output".into())
        .spawn(move || {
            let mut bytes = 0usize;
            let mut buffer = [0u8; 4096];
            let mut line = Vec::new();
            while !cancelled.load(Ordering::Acquire) {
                let count = match reader.read(&mut buffer) {
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        continue;
                    }
                    Err(_) => {
                        let _ = send(
                            &tx,
                            Output::Diagnostic("CLI output was interrupted.".into()),
                            &cancelled,
                        );
                        break;
                    }
                };
                bytes = bytes.saturating_add(count);
                if bytes > 16_777_216 {
                    let _ = send(&tx, Output::Overflow, &cancelled);
                    break;
                }
                for byte in &buffer[..count] {
                    line.push(*byte);
                    if line.len() > 262_144 {
                        let _ = send(&tx, Output::Overflow, &cancelled);
                        return;
                    }
                    if *byte == b'\n' && !send_line(&tx, &mut line, diagnostic, &cancelled) {
                        return;
                    }
                }
                if count == 0 {
                    if !line.is_empty() {
                        let _ = send_line(&tx, &mut line, diagnostic, &cancelled);
                    }
                    let _ = send(&tx, Output::End, &cancelled);
                    break;
                }
            }
        })
}

fn send_line(
    tx: &SyncSender<Output>,
    line: &mut Vec<u8>,
    diagnostic: bool,
    cancelled: &AtomicBool,
) -> bool {
    let bytes = std::mem::take(line);
    let output = if diagnostic {
        Output::Diagnostic(
            String::from_utf8_lossy(&bytes)
                .chars()
                .filter(|c| !c.is_control() || *c == '\t')
                .take(2048)
                .collect(),
        )
    } else {
        Output::Line(bytes)
    };
    send(tx, output, cancelled)
}
