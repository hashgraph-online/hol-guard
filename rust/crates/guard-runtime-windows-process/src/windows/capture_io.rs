use super::*;
use std::sync::{mpsc, LazyLock};
use winapi::shared::winerror::{
    ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED,
};
use winapi::um::fileapi::{ReadFile, WriteFile};
use winapi::um::ioapiset::{CancelIoEx, GetOverlappedResult};
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::synchapi::CreateEventW;

const BUFFER_BYTES: usize = 8192;
struct Resources {
    handle: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    _event: OwnedHandle,
    buffer: Box<[u8; BUFFER_BYTES]>,
}
// SAFETY: The OVERLAPPED and data buffer are exclusively owned, heap-pinned
// allocations. Only this module submits operations, and transfer occurs after
// cancellation with no caller-borrowed pointers or concurrent access.
unsafe impl Send for Resources {}

static REAPER: LazyLock<Option<mpsc::Sender<Resources>>> = LazyLock::new(|| {
    let (sender, receiver) = mpsc::channel::<Resources>();
    std::thread::Builder::new()
        .name("guard-win-io-reaper".into())
        .spawn(move || {
            for mut resources in receiver {
                let mut count = 0;
                let completed = unsafe {
                    GetOverlappedResult(
                        resources.handle.as_raw_handle() as HANDLE,
                        &mut *resources.overlapped,
                        &mut count,
                        TRUE,
                    )
                };
                if completed == FALSE
                    && !matches!(
                        unsafe { GetLastError() },
                        ERROR_OPERATION_ABORTED | winapi::shared::winerror::ERROR_BROKEN_PIPE
                    )
                {
                    // An unverified operation must never outlive its allocation.
                    std::mem::forget(resources);
                }
            }
        })
        .ok()
        .map(|_| sender)
});

fn retain_until_completed(resources: Resources) {
    match &*REAPER {
        Some(sender) => {
            if let Err(error) = sender.send(resources) {
                std::mem::forget(error.0);
            }
        }
        None => std::mem::forget(resources),
    }
}

pub(super) struct Operation {
    resources: Option<Resources>,
    pending: bool,
    used: usize,
}

impl Operation {
    pub(super) fn new(handle: OwnedHandle) -> io::Result<Self> {
        let event = unsafe { CreateEventW(null_mut(), TRUE, FALSE, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let event = unsafe { OwnedHandle::from_raw_handle(event as RawHandle) };
        let mut overlapped = Box::new(unsafe { zeroed::<OVERLAPPED>() });
        overlapped.hEvent = event.as_raw_handle() as HANDLE;
        Ok(Self {
            resources: Some(Resources {
                handle,
                overlapped,
                _event: event,
                buffer: Box::new([0; BUFFER_BYTES]),
            }),
            pending: false,
            used: 0,
        })
    }

    pub(super) fn buffer(&self, count: usize) -> &[u8] {
        &self.resources.as_ref().unwrap().buffer[..count]
    }

    pub(super) fn connect(mut self) -> io::Result<Self> {
        let resources = self.resources.as_mut().unwrap();
        if unsafe {
            winapi::um::namedpipeapi::ConnectNamedPipe(
                resources.handle.as_raw_handle() as HANDLE,
                &mut *resources.overlapped,
            )
        } == FALSE
        {
            let error = unsafe { GetLastError() };
            if error == ERROR_IO_PENDING {
                self.pending = true;
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "pipe connection incomplete",
                ));
            }
            if error != winapi::shared::winerror::ERROR_PIPE_CONNECTED {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
        }
        // The inheritable client was opened before ConnectNamedPipe. No caller
        // can learn the unpredictable pipe name or race this connection.
        Ok(self)
    }

    fn start(&mut self, write: bool, input: &[u8]) -> io::Result<Option<usize>> {
        let resources = self.resources.as_mut().unwrap();
        self.used = if write {
            input.len().min(BUFFER_BYTES)
        } else {
            BUFFER_BYTES
        };
        if write {
            resources.buffer[..self.used].copy_from_slice(&input[..self.used]);
        }
        let event = resources.overlapped.hEvent;
        *resources.overlapped = unsafe { zeroed() };
        resources.overlapped.hEvent = event;
        let mut count = 0;
        let success = unsafe {
            if write {
                WriteFile(
                    resources.handle.as_raw_handle() as HANDLE,
                    resources.buffer.as_ptr().cast(),
                    self.used as DWORD,
                    &mut count,
                    &mut *resources.overlapped,
                )
            } else {
                ReadFile(
                    resources.handle.as_raw_handle() as HANDLE,
                    resources.buffer.as_mut_ptr().cast(),
                    self.used as DWORD,
                    &mut count,
                    &mut *resources.overlapped,
                )
            }
        };
        if success != FALSE {
            if count as usize > self.used {
                return Err(io::Error::other("invalid pipe byte count"));
            }
            return Ok(Some(count as usize));
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_IO_PENDING {
            self.pending = true;
            return Ok(None);
        }
        if error == winapi::shared::winerror::ERROR_BROKEN_PIPE {
            return Ok(Some(0));
        }
        Err(io::Error::from_raw_os_error(error as i32))
    }

    pub(super) fn read(&mut self) -> io::Result<Option<usize>> {
        if self.pending {
            self.poll()
        } else {
            self.start(false, &[])
        }
    }
    pub(super) fn write(&mut self, input: &[u8]) -> io::Result<Option<usize>> {
        if self.pending {
            self.poll()
        } else {
            self.start(true, input)
        }
    }

    fn poll(&mut self) -> io::Result<Option<usize>> {
        let resources = self.resources.as_mut().unwrap();
        let mut count = 0;
        if unsafe {
            GetOverlappedResult(
                resources.handle.as_raw_handle() as HANDLE,
                &mut *resources.overlapped,
                &mut count,
                FALSE,
            )
        } != FALSE
        {
            self.pending = false;
            if count as usize > self.used {
                return Err(io::Error::other("invalid pipe byte count"));
            }
            return Ok(Some(count as usize));
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_IO_INCOMPLETE {
            return Ok(None);
        }
        self.pending = false;
        if error == winapi::shared::winerror::ERROR_BROKEN_PIPE {
            return Ok(Some(0));
        }
        Err(io::Error::from_raw_os_error(error as i32))
    }

    pub(super) fn request_cancel(&mut self) -> io::Result<()> {
        if !self.pending {
            return Ok(());
        }
        let resources = self.resources.as_mut().unwrap();
        if unsafe {
            CancelIoEx(
                resources.handle.as_raw_handle() as HANDLE,
                &mut *resources.overlapped,
            )
        } == FALSE
        {
            let error = unsafe { GetLastError() };
            if error != ERROR_NOT_FOUND {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
        }
        Ok(())
    }

    pub(super) fn finish_cancel(&mut self, deadline: Instant) -> io::Result<()> {
        if !self.pending {
            return Ok(());
        }
        loop {
            match self.poll() {
                Ok(Some(_)) => return Ok(()),
                Err(error) if error.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) => {
                    return Ok(())
                }
                Err(error) => return Err(error),
                Ok(None) => {}
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cleanup_incomplete",
                ));
            }
            std::thread::sleep(
                Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if !self.pending {
            return;
        }
        let mut resources = self.resources.take().unwrap();
        unsafe {
            CancelIoEx(
                resources.handle.as_raw_handle() as HANDLE,
                &mut *resources.overlapped,
            );
        }
        retain_until_completed(resources);
    }
}
