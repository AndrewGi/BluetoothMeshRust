//! Asynchronous `Mutex` and `MutexGuard`.
#[derive(Copy, Clone)]
pub struct TryLockError(());
#[cfg(feature = "tokio")]
pub mod mutex_impl {
    use crate::asyncs::sync::mutex::TryLockError;

    pub type ActualMutex<T> = tokio::sync::Mutex<T>;
    pub type ActualMutexGuard<'a, T> = tokio::sync::MutexGuard<'a, T>;
    #[derive(Debug)]
    pub struct MutexImpl<T>(ActualMutex<T>);
    impl<T> MutexImpl<T> {
        pub fn new(t: T) -> Self {
            Self(ActualMutex::new(t))
        }
        pub fn into_inner(self) -> T {
            self.0.into_inner()
        }
        pub fn try_lock(&self) -> Result<MutexGuardImpl<T>, TryLockError> {
            self.0
                .try_lock()
                .map(MutexGuardImpl)
                .map_err(|_| TryLockError(()))
        }
        pub async fn lock(&self) -> MutexGuardImpl<'_, T> {
            MutexGuardImpl(self.0.lock().await)
        }
    }

    pub struct MutexGuardImpl<'a, T>(ActualMutexGuard<'a, T>);
    impl<T> core::ops::Deref for MutexGuardImpl<'_, T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }
    impl<T> core::ops::DerefMut for MutexGuardImpl<'_, T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.0.deref_mut()
        }
    }
}
#[derive(Debug)]
pub struct Mutex<T>(mutex_impl::MutexImpl<T>);

impl<T> Mutex<T> {
    pub fn new(t: T) -> Self {
        Self(mutex_impl::MutexImpl::new(t))
    }
    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }
    pub fn try_lock(&self) -> Result<MutexGuard<T>, TryLockError> {
        self.0
            .try_lock()
            .map(MutexGuard)
            .map_err(|_| TryLockError(()))
    }
    pub async fn lock(&self) -> MutexGuard<'_, T> {
        MutexGuard(self.0.lock().await)
    }
}

pub struct MutexGuard<'a, T>(mutex_impl::MutexGuardImpl<'a, T>);
impl<T> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}
impl<T> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}
