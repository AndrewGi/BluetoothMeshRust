use crate::asyncs::sync::mpsc::mpsc_impl::{ReceiverImpl, SenderImpl};

#[derive(Copy, Clone)]
pub struct TryRecvError(());
pub enum TrySendError<T> {
    Full(T),
    Closed(T),
}
pub struct SendError<T>(pub T);
#[cfg(feature = "tokio")]
pub mod mpsc_impl {
    use crate::asyncs::sync::mpsc::{SendError, TryRecvError, TrySendError};
    use tokio::sync::mpsc::Sender;

    pub struct ReceiverImpl<T>(tokio::sync::mpsc::Receiver<T>);
    impl<T> ReceiverImpl<T> {
        pub async fn recv(&mut self) -> Option<T> {
            self.0.recv().await
        }
        pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
            self.0.try_recv().map_err(|_| TryRecvError(()))
        }
        pub fn close(&mut self) {
            self.0.close();
        }
    }
    impl<T> From<tokio::sync::mpsc::Receiver<T>> for ReceiverImpl<T> {
        fn from(r: tokio::sync::mpsc::Receiver<T>) -> Self {
            Self(r)
        }
    }

    impl<T> From<tokio::sync::mpsc::error::TrySendError<T>> for TrySendError<T> {
        fn from(e: tokio::sync::mpsc::error::TrySendError<T>) -> Self {
            match e {
                tokio::sync::mpsc::error::TrySendError::Full(t) => TrySendError::Full(t),
                tokio::sync::mpsc::error::TrySendError::Closed(t) => TrySendError::Closed(t),
            }
        }
    }

    pub struct SenderImpl<T>(tokio::sync::mpsc::Sender<T>);
    impl<T> Clone for SenderImpl<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<T> SenderImpl<T> {
        pub fn try_send(&mut self, message: T) -> Result<(), TrySendError<T>> {
            self.0.try_send(message).map_err(TrySendError::from)
        }
        pub async fn send(&mut self, message: T) -> Result<(), SendError<T>> {
            self.0.send(message).await.map_err(|e| SendError(e.0))
        }
    }
    impl<T> From<tokio::sync::mpsc::Sender<T>> for SenderImpl<T> {
        fn from(s: Sender<T>) -> Self {
            Self(s)
        }
    }
    pub fn channel<T>(buffer_size: usize) -> (SenderImpl<T>, ReceiverImpl<T>) {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer_size);
        (SenderImpl(tx), ReceiverImpl(rx))
    }
}

pub struct Receiver<T>(ReceiverImpl<T>);
impl<T> Receiver<T> {
    pub async fn recv(&mut self) -> Option<T> {
        self.0.recv().await
    }
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        self.0.try_recv()
    }
}
pub struct Sender<T>(SenderImpl<T>);

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> Sender<T> {
    pub async fn send(&mut self, message: T) -> Result<(), SendError<T>> {
        self.0.send(message).await
    }
    pub fn try_send(&mut self, message: T) -> Result<(), TrySendError<T>> {
        self.0.try_send(message)
    }
}
pub fn channel<T>(buffer_size: usize) -> (Sender<T>, Receiver<T>) {
    let (tx, rx) = mpsc_impl::channel(buffer_size);
    (Sender(tx), Receiver(rx))
}
