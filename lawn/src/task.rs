use std::future::Future;

pub fn block_on_async<T>(f: T) -> T::Output
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    tokio::task::spawn(async move {
        let _ = tx.send(f.await);
    });
    tokio::task::block_in_place(|| rx.recv().unwrap())
}
