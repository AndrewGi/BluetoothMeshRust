//! Arbitrary Scheduler module mostly used for Packet Schedule but also for Publish scheduling and
//! other timing related things.
use crate::timestamp::TimestampTrait;
use alloc::collections::BinaryHeap;
use core::cmp::Ordering;
use core::time::Duration;

#[derive(Debug)]
pub struct TimeQueueEntry<T, Timestamp: TimestampTrait> {
    timestamp: Timestamp,
    item: T,
}
impl<T, Timestamp: TimestampTrait> TimeQueueEntry<T, Timestamp> {
    #[must_use]
    pub fn new(timestamp: Timestamp, item: T) -> TimeQueueEntry<T, Timestamp> {
        TimeQueueEntry { timestamp, item }
    }
    #[must_use]
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}
impl<T: Clone, Timestamp: TimestampTrait> Clone for TimeQueueEntry<T, Timestamp> {
    #[must_use]
    fn clone(&self) -> Self {
        TimeQueueEntry {
            timestamp: self.timestamp,
            item: self.item.clone(),
        }
    }
}
impl<T, Timestamp: TimestampTrait> AsRef<T> for TimeQueueEntry<T, Timestamp> {
    #[must_use]
    fn as_ref(&self) -> &T {
        &self.item
    }
}
impl<T, Timestamp: TimestampTrait> AsMut<T> for TimeQueueEntry<T, Timestamp> {
    #[must_use]
    fn as_mut(&mut self) -> &mut T {
        &mut self.item
    }
}
impl<T, Timestamp: TimestampTrait> PartialOrd for TimeQueueEntry<T, Timestamp> {
    #[must_use]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.timestamp.partial_cmp(&other.timestamp)
    }
}
impl<T, Timestamp: TimestampTrait> PartialEq for TimeQueueEntry<T, Timestamp> {
    #[must_use]
    fn eq(&self, other: &Self) -> bool {
        self.timestamp.eq(&other.timestamp)
    }
}
impl<T, Timestamp: TimestampTrait> Eq for TimeQueueEntry<T, Timestamp> {}
impl<T, Timestamp: TimestampTrait> Ord for TimeQueueEntry<T, Timestamp> {
    #[must_use]
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}
#[derive(Debug, Default)]
pub struct TimeQueue<T, Timestamp: TimestampTrait> {
    priority_queue: BinaryHeap<TimeQueueEntry<T, Timestamp>>,
}
impl<T: Clone, Timestamp: TimestampTrait> Clone for TimeQueue<T, Timestamp> {
    #[must_use]
    fn clone(&self) -> Self {
        TimeQueue {
            priority_queue: self.priority_queue.clone(),
        }
    }
}
impl<T, Timestamp: TimestampTrait> TimeQueue<T, Timestamp> {
    #[must_use]
    pub fn new() -> TimeQueue<T, Timestamp> {
        TimeQueue {
            priority_queue: BinaryHeap::default(),
        }
    }
    #[must_use]
    pub fn with_capacity(capacity: usize) -> TimeQueue<T, Timestamp> {
        TimeQueue {
            priority_queue: BinaryHeap::with_capacity(capacity),
        }
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.priority_queue.len()
    }
    #[must_use]
    pub fn peek(&self) -> Option<&TimeQueueEntry<T, Timestamp>> {
        self.priority_queue.peek()
    }
    #[must_use]
    pub fn peek_item(&self) -> Option<&T> {
        Some(self.peek()?.as_ref())
    }
    #[must_use]
    pub fn peek_timestamp(&self) -> Option<Timestamp> {
        Some(self.peek()?.timestamp())
    }
    /*
    pub fn peek_item_mut(&mut self) -> Option<&mut T> {
        Some(&mut self.priority_queue.peek_mut()?.item)
    }
    */
    pub fn push(&mut self, timestamp: Timestamp, item: T) {
        self.priority_queue
            .push(TimeQueueEntry::new(timestamp, item))
    }
    pub fn pop_force(&mut self) -> Option<TimeQueueEntry<T, Timestamp>> {
        self.priority_queue.pop()
    }
    pub fn pop_ready(&mut self) -> Option<TimeQueueEntry<T, Timestamp>> {
        if self.next_is_ready() {
            self.pop_force()
        } else {
            None
        }
    }
    pub fn pop_item_ready(&mut self) -> Option<T> {
        Some(self.pop_ready()?.item)
    }
    pub fn pop_item_force(&mut self) -> Option<T> {
        Some(self.pop_force()?.item)
    }
    #[must_use]
    pub fn time_until_next(&self) -> Option<Duration> {
        Some(
            self.peek_timestamp()?
                .until(Timestamp::now())
                .unwrap_or(Duration::default()),
        )
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.priority_queue.is_empty()
    }
    #[must_use]
    pub fn next_is_ready(&self) -> bool {
        !self.is_empty() && self.time_until_next().is_none()
    }
    pub fn map_ready_item(&mut self, mut func: impl FnMut(T)) {
        while let Some(i) = self.pop_item_ready() {
            func(i)
        }
    }
    pub fn clear(&mut self) {
        self.priority_queue.clear()
    }
    pub fn reserve(&mut self, additional: usize) {
        self.priority_queue.reserve(additional)
    }
    pub fn shrink_to_fit(&mut self) {
        self.priority_queue.shrink_to_fit()
    }
    #[must_use]
    pub fn into_heap(self) -> BinaryHeap<TimeQueueEntry<T, Timestamp>> {
        self.priority_queue
    }
    #[must_use]
    pub fn from_heap(heap: BinaryHeap<TimeQueueEntry<T, Timestamp>>) -> TimeQueue<T, Timestamp> {
        TimeQueue {
            priority_queue: heap,
        }
    }
}
/*
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[repr(transparent)]
pub struct TimeQueueSlotKey(slotmap::KeyData);

impl From<slotmap::KeyData> for TimeQueueSlotKey {
    #[must_use]
    fn from(k: slotmap::KeyData) -> Self {
        TimeQueueSlotKey(k)
    }
}

impl From<TimeQueueSlotKey> for slotmap::KeyData {
    #[must_use]
    fn from(k: TimeQueueSlotKey) -> Self {
        k.0
    }
}

impl slotmap::Key for TimeQueueSlotKey {}

slotmap::__serialize_key!(TimeQueueSlotKey);

/// TimeQueue but its items `T` are stored in a slotmap and the keys are storing in the TimeQueue.
/// When the binary heap in the TimeQueue needs to sift, its more efficient to sift small
/// slotmap keys than `T`s (if `size_of::<T>()` is big). If `T` is small, just use a regular
/// TimeQueue.
pub struct SlottedTimeQueue<T, Timestamp: TimestampTrait> {
    queue: TimeQueue<TimeQueueSlotKey, Timestamp>,
    slots: slotmap::DenseSlotMap<TimeQueueSlotKey, T>,
}

impl<T, Timestamp: TimestampTrait> SlottedTimeQueue<T, Timestamp> {
    #[must_use]
    pub fn with_capacity(capacity: usize) -> SlottedTimeQueue<T, Timestamp> {
        SlottedTimeQueue {
            queue: TimeQueue::with_capacity(capacity),
            slots: slotmap::DenseSlotMap::with_capacity_and_key(capacity),
        }
    }
    pub fn push(&mut self, by_when: Timestamp, item: T) -> TimeQueueSlotKey {
        let slot = self.slots.insert(item);
        self.queue.push(by_when, slot);
        slot
    }
    #[must_use]
    pub fn get_slot_item(&self, slot: TimeQueueSlotKey) -> Option<&T> {
        self.slots.get(slot)
    }
    pub fn map_ready(&mut self, mut func: impl FnMut(T)) {
        let queue = &mut self.queue;
        let slots = &mut self.slots;
        queue.map_ready_item(|slot| {
            if let Some(item) = slots.remove(slot) {
                func(item)
            }
        });
    }
    pub fn pop_force(&mut self) -> Option<(Timestamp, T)> {
        let entry = self.queue.pop_force()?;
        let timestamp = entry.timestamp;
        let item = self.slots.remove(entry.item)?;
        Some((timestamp, item))
    }
    pub fn pop_ready(&mut self) -> Option<(Timestamp, T)> {
        if self.queue.next_is_ready() {
            self.pop_force()
        } else {
            None
        }
    }
    #[must_use]
    pub fn peek_timestamp(&self) -> Option<Timestamp> {
        self.queue.peek_timestamp()
    }
    #[must_use]
    pub fn slots_ref(&self) -> &DenseSlotMap<TimeQueueSlotKey, T> {
        &self.slots
    }
    #[must_use]
    pub fn slots_mut(&mut self) -> &mut DenseSlotMap<TimeQueueSlotKey, T> {
        &mut self.slots
    }
    pub fn remove(&mut self, key: TimeQueueSlotKey) -> Option<T> {
        self.slots.remove(key)
    }
    /// Reschedules the item by canceling the current queue entry and inserting a new one.
    /// The QueueEntry is still in the TimeQueue but its corresponding slot has moved and is invalid.
    pub fn reschedule(
        &mut self,
        key: TimeQueueSlotKey,
        new_timestamp: Timestamp,
    ) -> Option<TimeQueueSlotKey> {
        //TODO: Write custom SlotMap so we can increment the Slot generation instead of remove/push.
        let item = self.remove(key)?;
        Some(self.push(new_timestamp, item))
    }
}
*/
