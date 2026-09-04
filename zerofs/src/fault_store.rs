//! A reusable fault-injecting object store for tests: a pass-through decorator
//! over any inner store whose writes can be partitioned or made to fail
//! transiently, and whose reads can fail or return short bodies. Generalizes the
//! one-off wrappers in `replication::zombie` (write partition) and
//! `length_checked_object_store`'s `ShortBodyStore` (truncated reads) into one
//! programmable harness, driven through a shared [`FaultControls`] handle.

use async_trait::async_trait;
use futures::stream::{self, BoxStream, StreamExt};
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, GetResultPayload, ListResult, MultipartUpload, ObjectMeta,
    ObjectStore, PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Knobs shared with the test driving the store. Everything defaults to "no fault".
#[derive(Debug, Default)]
pub struct FaultControls {
    /// While true, every write (put/delete/copy) fails fast: a write partition.
    partition_writes: AtomicBool,
    /// Fail the next N `get` calls with a transient error, then resume.
    fail_next_gets: AtomicUsize,
    /// Fail the next N `put` calls before applying them, then resume.
    fail_next_puts: AtomicUsize,
    /// Apply the next N `put` calls, then return a transient response error.
    fail_after_puts: AtomicUsize,
    /// Apply the next N SlateDB manifest PUTs, then return a transient response
    /// error. Non-manifest objects do not consume this budget.
    fail_after_manifest_puts: AtomicUsize,
    manifest_puts: AtomicUsize,
    manifest_response_losses: AtomicUsize,
    #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
    block_next_manifest_after_apply: AtomicBool,
    #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
    maximum_puts: AtomicUsize,
    #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
    maximum_put_bytes: AtomicUsize,
    #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
    attempted_put_bytes: AtomicUsize,
    #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
    put_locations: std::sync::Mutex<Vec<String>>,
    /// Return a body `truncate_bytes` short of the claimed length on the next N gets.
    truncate_next_gets: AtomicUsize,
    truncate_bytes: AtomicUsize,
    gets: AtomicUsize,
    puts: AtomicUsize,
}

impl FaultControls {
    pub fn partition_writes(&self, on: bool) {
        self.partition_writes.store(on, Ordering::SeqCst);
    }
    pub fn fail_gets(&self, n: usize) {
        self.fail_next_gets.store(n, Ordering::SeqCst);
    }
    pub fn fail_puts(&self, n: usize) {
        self.fail_next_puts.store(n, Ordering::SeqCst);
    }
    pub fn fail_puts_after_apply(&self, n: usize) {
        self.fail_after_puts.store(n, Ordering::SeqCst);
    }
    pub fn fail_manifest_puts_after_apply(&self, n: usize) {
        self.fail_after_manifest_puts.store(n, Ordering::SeqCst);
    }
    /// Make the next `n` gets return a body `by` bytes short of the claimed length.
    pub fn truncate_gets(&self, n: usize, by: usize) {
        self.truncate_bytes.store(by, Ordering::SeqCst);
        self.truncate_next_gets.store(n, Ordering::SeqCst);
    }
    pub fn get_count(&self) -> usize {
        self.gets.load(Ordering::SeqCst)
    }
    pub fn put_count(&self) -> usize {
        self.puts.load(Ordering::SeqCst)
    }
    pub fn manifest_put_count(&self) -> usize {
        self.manifest_puts.load(Ordering::SeqCst)
    }
    pub fn manifest_response_loss_count(&self) -> usize {
        self.manifest_response_losses.load(Ordering::SeqCst)
    }
    #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
    #[allow(dead_code)]
    pub(crate) fn block_manifest_after_apply(&self) {
        assert!(
            !self
                .block_next_manifest_after_apply
                .swap(true, Ordering::SeqCst),
            "manifest post-apply blocker already armed"
        );
    }
    #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
    pub(crate) fn set_put_limits(&self, maximum_puts: usize, maximum_put_bytes: usize) {
        assert!(maximum_puts > 0 && maximum_put_bytes > 0);
        assert_eq!(self.put_count(), 0);
        assert_eq!(self.attempted_put_bytes.load(Ordering::SeqCst), 0);
        self.maximum_puts.store(maximum_puts, Ordering::SeqCst);
        self.maximum_put_bytes
            .store(maximum_put_bytes, Ordering::SeqCst);
    }
    #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
    pub(crate) fn put_locations(&self) -> Vec<String> {
        self.put_locations.lock().unwrap().clone()
    }
}

/// Decrement `counter` if positive; returns whether a unit was taken.
fn take_one(counter: &AtomicUsize) -> bool {
    let mut cur = counter.load(Ordering::SeqCst);
    while cur > 0 {
        match counter.compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(actual) => cur = actual,
        }
    }
    false
}

#[derive(Debug)]
pub struct FaultStore {
    inner: Arc<dyn ObjectStore>,
    ctl: Arc<FaultControls>,
}

impl FaultStore {
    /// Returns the store and its shared controls (default: no fault).
    pub fn new(inner: Arc<dyn ObjectStore>) -> (Arc<Self>, Arc<FaultControls>) {
        let ctl = Arc::new(FaultControls::default());
        (
            Arc::new(Self {
                inner,
                ctl: ctl.clone(),
            }),
            ctl,
        )
    }

    fn transient(op: &'static str) -> object_store::Error {
        object_store::Error::Generic {
            store: "FaultStore",
            source: format!("injected transient fault on {op}").into(),
        }
    }

    fn check_writable(&self, op: &'static str) -> object_store::Result<()> {
        if self.ctl.partition_writes.load(Ordering::SeqCst) {
            return Err(Self::transient(op));
        }
        Ok(())
    }
}

impl Display for FaultStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "FaultStore({})", self.inner)
    }
}

#[async_trait]
impl ObjectStore for FaultStore {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
        self.ctl
            .put_locations
            .lock()
            .unwrap()
            .push(format!("put_opts {location}"));
        self.ctl.puts.fetch_add(1, Ordering::SeqCst);
        #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
        {
            let maximum_puts = self.ctl.maximum_puts.load(Ordering::SeqCst);
            if maximum_puts > 0 && self.ctl.put_count() > maximum_puts {
                return Err(Self::transient("put count limit"));
            }
            let payload_bytes = payload.content_length();
            let previous = self
                .ctl
                .attempted_put_bytes
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    current.checked_add(payload_bytes)
                })
                .map_err(|_| Self::transient("put byte counter overflow"))?;
            let maximum_put_bytes = self.ctl.maximum_put_bytes.load(Ordering::SeqCst);
            if maximum_put_bytes > 0
                && previous
                    .checked_add(payload_bytes)
                    .is_none_or(|total| total > maximum_put_bytes)
            {
                return Err(Self::transient("put byte limit"));
            }
        }
        let is_manifest = location.extension() == Some("manifest");
        if is_manifest {
            self.ctl.manifest_puts.fetch_add(1, Ordering::SeqCst);
        }
        self.check_writable("put")?;
        if take_one(&self.ctl.fail_next_puts) {
            return Err(Self::transient("put"));
        }
        let result = self.inner.put_opts(location, payload, opts).await?;
        #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
        if is_manifest
            && self
                .ctl
                .block_next_manifest_after_apply
                .swap(false, Ordering::SeqCst)
        {
            crate::fs::workspace_barrier::foundation_manifest_applied_before_response().await;
        }
        let generic_response_loss = take_one(&self.ctl.fail_after_puts);
        let manifest_response_loss = is_manifest && take_one(&self.ctl.fail_after_manifest_puts);
        if manifest_response_loss {
            self.ctl
                .manifest_response_losses
                .fetch_add(1, Ordering::SeqCst);
        }
        if generic_response_loss || manifest_response_loss {
            return Err(Self::transient("put response"));
        }
        Ok(result)
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        #[cfg(all(test, feature = "rhizome-workspace-barrier-core"))]
        if self.ctl.maximum_puts.load(Ordering::SeqCst) > 0 {
            return Err(Self::transient("multipart forbidden by put budget"));
        }
        self.check_writable("put_multipart")?;
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(
        &self,
        location: &Path,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        self.ctl.gets.fetch_add(1, Ordering::SeqCst);
        if take_one(&self.ctl.fail_next_gets) {
            return Err(Self::transient("get"));
        }
        let head = options.head;
        let result = self.inner.get_opts(location, options).await?;
        // Head replies carry no body; only short-circuit truncation for them.
        if head || !take_one(&self.ctl.truncate_next_gets) {
            return Ok(result);
        }
        let by = self.ctl.truncate_bytes.load(Ordering::SeqCst);
        let meta = result.meta.clone();
        let range = result.range.clone();
        let attributes = result.attributes.clone();
        let full = result.bytes().await?;
        let short = full.slice(0..full.len().saturating_sub(by));
        Ok(GetResult {
            payload: GetResultPayload::Stream(stream::once(async move { Ok(short) }).boxed()),
            meta,
            range,
            attributes,
            extensions: Default::default(),
        })
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<Path>>,
    ) -> BoxStream<'static, object_store::Result<Path>> {
        // A write partition fails every delete fast (one yield per input, as the
        // provided `ObjectStoreExt::delete` and bulk callers expect).
        if self.ctl.partition_writes.load(Ordering::SeqCst) {
            return locations
                .map(|loc| loc.and_then(|_| Err(Self::transient("delete"))))
                .boxed();
        }
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &Path,
        to: &Path,
        options: CopyOptions,
    ) -> object_store::Result<()> {
        self.check_writable("copy")?;
        self.inner.copy_opts(from, to, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "rhizome-workspace-barrier-core")]
    use futures::TryStreamExt;
    use object_store::ObjectStoreExt;
    use object_store::memory::InMemory;

    #[tokio::test]
    async fn fail_gets_then_recovers() {
        let (store, ctl) = FaultStore::new(Arc::new(InMemory::new()));
        let path = Path::from("k");
        store.put(&path, b"hello".to_vec().into()).await.unwrap();

        ctl.fail_gets(2);
        assert!(store.get(&path).await.is_err());
        assert!(store.get(&path).await.is_err());

        let got = store.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(&got[..], b"hello");
        assert_eq!(
            store.get(&path).await.unwrap().bytes().await.unwrap().len(),
            5
        );
        assert_eq!(ctl.get_count(), 4);
    }

    #[tokio::test]
    async fn partition_blocks_writes_but_not_reads() {
        let (store, ctl) = FaultStore::new(Arc::new(InMemory::new()));
        let path = Path::from("k");
        store.put(&path, b"v".to_vec().into()).await.unwrap();

        ctl.partition_writes(true);
        assert!(store.put(&path, b"v2".to_vec().into()).await.is_err());
        // Reads keep working while writes are partitioned.
        let got = store.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(&got[..], b"v");

        ctl.partition_writes(false);
        store.put(&path, b"v3".to_vec().into()).await.unwrap();
        let got = store.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(&got[..], b"v3");
    }

    #[tokio::test]
    async fn fail_puts_then_recovers() {
        let (store, ctl) = FaultStore::new(Arc::new(InMemory::new()));
        let path = Path::from("k");

        ctl.fail_puts(1);
        assert!(store.put(&path, b"a".to_vec().into()).await.is_err());
        store.put(&path, b"b".to_vec().into()).await.unwrap();

        let got = store.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(&got[..], b"b");
        assert_eq!(ctl.put_count(), 2);
    }

    #[tokio::test]
    async fn truncates_a_bounded_number_of_gets() {
        let (store, ctl) = FaultStore::new(Arc::new(InMemory::new()));
        let path = Path::from("k");
        store.put(&path, vec![7u8; 100].into()).await.unwrap();

        ctl.truncate_gets(2, 40);
        assert_eq!(
            store.get(&path).await.unwrap().bytes().await.unwrap().len(),
            60
        );
        assert_eq!(
            store.get(&path).await.unwrap().bytes().await.unwrap().len(),
            60
        );
        // Budget exhausted: the full body comes back.
        assert_eq!(
            store.get(&path).await.unwrap().bytes().await.unwrap().len(),
            100
        );
    }

    #[tokio::test]
    async fn manifest_response_loss_does_not_consume_on_other_puts() {
        let (store, ctl) = FaultStore::new(Arc::new(InMemory::new()));
        ctl.fail_manifest_puts_after_apply(1);
        store
            .put(&Path::from("segment/1"), b"segment".to_vec().into())
            .await
            .unwrap();
        let manifest = Path::from("db/manifest/00000000000000000001.manifest");
        assert!(
            store
                .put(&manifest, b"manifest".to_vec().into())
                .await
                .is_err()
        );
        assert_eq!(ctl.manifest_put_count(), 1);
        assert_eq!(ctl.manifest_response_loss_count(), 1);
        assert_eq!(
            store.get(&manifest).await.unwrap().bytes().await.unwrap(),
            bytes::Bytes::from_static(b"manifest")
        );
    }

    #[cfg(feature = "rhizome-workspace-barrier-core")]
    #[tokio::test]
    async fn put_limits_reject_before_forwarding() {
        let inner = Arc::new(InMemory::new());
        let (store, ctl) = FaultStore::new(inner.clone());
        ctl.set_put_limits(2, 4);
        store
            .put(&Path::from("a"), b"aa".to_vec().into())
            .await
            .unwrap();
        store
            .put(&Path::from("b"), b"bb".to_vec().into())
            .await
            .unwrap();
        assert!(
            store
                .put(&Path::from("c"), Vec::<u8>::new().into())
                .await
                .is_err()
        );
        assert_eq!(
            inner
                .list(None)
                .try_collect::<Vec<_>>()
                .await
                .unwrap()
                .len(),
            2
        );

        let inner = Arc::new(InMemory::new());
        let (store, ctl) = FaultStore::new(inner.clone());
        ctl.set_put_limits(8, 3);
        store
            .put(&Path::from("exact"), b"abc".to_vec().into())
            .await
            .unwrap();
        assert!(
            store
                .put(&Path::from("over"), b"d".to_vec().into())
                .await
                .is_err()
        );
        assert_eq!(
            inner
                .list(None)
                .try_collect::<Vec<_>>()
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(store.put_multipart(&Path::from("multipart")).await.is_err());
        assert_eq!(
            inner
                .list(None)
                .try_collect::<Vec<_>>()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[cfg(feature = "rhizome-workspace-barrier-core")]
    #[tokio::test]
    async fn concurrent_puts_cannot_exceed_the_forwarded_byte_budget() {
        let inner = Arc::new(InMemory::new());
        let (store, ctl) = FaultStore::new(inner.clone());
        ctl.set_put_limits(64, 64);
        let attempts = (0..32).map(|index| {
            let store = store.clone();
            async move {
                store
                    .put(
                        &Path::from(format!("key-{index}")),
                        vec![index as u8; 4].into(),
                    )
                    .await
            }
        });
        let results = futures::future::join_all(attempts).await;
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 16);
        let retained = inner.list(None).try_collect::<Vec<_>>().await.unwrap();
        assert_eq!(retained.len(), 16);
        assert_eq!(retained.iter().map(|object| object.size).sum::<u64>(), 64);
    }
}
