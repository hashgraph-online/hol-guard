use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(super) fn spawn_workers<T, F>(
    count: usize,
    receiver: Receiver<T>,
    handler: F,
) -> Vec<JoinHandle<()>>
where
    T: Send + 'static,
    F: Fn(T) + Send + Sync + 'static,
{
    let receiver = Arc::new(Mutex::new(receiver));
    let handler = Arc::new(handler);
    (0..count)
        .map(|_| {
            let receiver = Arc::clone(&receiver);
            let handler = Arc::clone(&handler);
            thread::spawn(move || loop {
                let next = match receiver.lock() {
                    Ok(guard) => guard.recv(),
                    Err(_) => return,
                };
                match next {
                    Ok(item) => handler(item),
                    Err(_) => return,
                }
            })
        })
        .collect()
}

// Stop admission first, then let authenticated work finish. A stuck or slow
// client must not retain the managed owner lock indefinitely.
pub(super) fn drain(workers: Vec<JoinHandle<()>>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while workers.iter().any(|worker| !worker.is_finished()) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    for worker in workers {
        if worker.is_finished() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    #[test]
    fn drain_finishes_admitted_work_after_senders_close() {
        let (sender, receiver) = sync_channel(1);
        let (completed, result) = sync_channel(1);
        let workers = spawn_workers(1, receiver, move |value: u8| {
            thread::sleep(Duration::from_millis(20));
            completed.send(value).unwrap();
        });
        sender.send(7).unwrap();
        drop(sender);
        drain(workers, Duration::from_secs(1));
        assert_eq!(result.try_recv().unwrap(), 7);
    }
}
