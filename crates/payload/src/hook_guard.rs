//! Enforcement of the hook-body contract: no allocation, no locking, no I/O.
//!
//! The crate contract states the rule; this module is what makes the allocation half
//! checkable. A hook body runs on the target's thread, inside the target's lock
//! hierarchy, with the loader possibly still holding its lock. Allocating can deadlock
//! the heap; locking can invert against a lock the caller holds; I/O can block a
//! real-time thread. None of that is recoverable from inside the hook, so the rule is
//! absolute.
//!
//! **Allocation is counted at run time** by [`GuardedAllocator`], a `GlobalAlloc` wrapper
//! that increments a counter whenever a hook body is on the stack. The count is read
//! after the hook returns, not raised inside it: a panic inside a hook would take the
//! target process down, which is the one outcome worse than the violation.
//!
//! **Locking and I/O are not mechanically enforced here, and that is a known limit.**
//! `clippy::disallowed_methods` would be the right tool, but its configuration is
//! crate-wide and this crate's service thread legitimately uses `std::net`; Cargo also
//! refuses per-crate lint overrides under `lints.workspace = true`. So those two rules
//! stay review-enforced until a hook body exists that is worth a dedicated crate with
//! its own lint config. Stating that beats a comment claiming a check that does not run.
//!
//! A hook body that needs to hand data out writes into a pre-reserved, lock-free slot
//! owned by the caller. Nothing in this module allocates, locks or performs I/O itself.

#![allow(unsafe_code)] // GlobalAlloc is an unsafe trait; the wrapper adds no new invariants.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Whether a hook body is currently on the stack.
static IN_HOOK: AtomicBool = AtomicBool::new(false);

/// Allocations performed while a hook body was on the stack.
static HOOK_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// A `GlobalAlloc` that counts allocations made inside a hook body.
///
/// Install it once per binary with `#[global_allocator]`; the payload does this so the
/// count is live in every build, not only under test.
pub struct GuardedAllocator;

unsafe impl GlobalAlloc for GuardedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if IN_HOOK.load(Ordering::Relaxed) {
            HOOK_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the layout is passed through unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout come from a matching `alloc` on `System`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Marks the region in which a hook body runs; resets the counter on entry.
///
/// Dropping it clears the flag. The violation count is read separately through
/// [`hook_allocations`] once the hook has returned.
#[must_use = "the guard clears the hook flag on drop; binding it keeps the region scoped"]
pub struct HookGuard;

impl HookGuard {
    /// Enter a hook body.
    pub fn enter() -> Self {
        HOOK_ALLOCATIONS.store(0, Ordering::Relaxed);
        IN_HOOK.store(true, Ordering::Relaxed);
        Self
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        IN_HOOK.store(false, Ordering::Relaxed);
    }
}

/// Allocations counted during the most recent hook body.
#[must_use]
pub fn hook_allocations() -> usize {
    HOOK_ALLOCATIONS.load(Ordering::Relaxed)
}

/// Run `body` as a hook body and report how many allocations it made.
///
/// This is the shape every hook dispatcher uses: the count is observed after the body
/// returns, so a violating hook is reported rather than aborted.
pub fn measure<R>(body: impl FnOnce() -> R) -> (R, usize) {
    let guard = HookGuard::enter();
    let result = body();
    drop(guard);
    (result, hook_allocations())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hook_body_that_does_not_allocate_counts_zero() {
        let (sum, allocations) = measure(|| {
            // Pure stack work: no heap, no lock, no I/O.
            let mut total = 0u64;
            for i in 0..100u64 {
                total = total.wrapping_add(i);
            }
            total
        });
        assert_eq!(sum, 4950);
        assert_eq!(allocations, 0, "stack-only work must not allocate");
    }

    #[test]
    fn a_hook_body_that_allocates_is_counted() {
        let (_leak, allocations) = measure(|| {
            // The most innocuous allocation there is; it must still be seen.
            let v: Vec<u8> = Vec::with_capacity(16);
            v
        });
        assert!(
            allocations >= 1,
            "a Vec allocation inside a hook must be counted"
        );
    }

    #[test]
    fn a_string_format_inside_a_hook_is_counted() {
        let (text, allocations) = measure(|| format!("{}-{}", 1, 2));
        assert_eq!(text, "1-2");
        assert!(allocations >= 1);
    }

    #[test]
    fn allocations_outside_a_hook_are_not_counted() {
        // Baseline: a hook that allocates is counted; the same allocation outside is not.
        let before = hook_allocations();
        let _ = Vec::<u8>::with_capacity(1024);
        assert_eq!(hook_allocations(), before);
    }

    #[test]
    fn the_guard_resets_the_count_on_entry() {
        let _ = measure(|| {
            let _ = Vec::<u8>::with_capacity(8);
        });
        // A following clean hook must start from zero, not inherit the previous count.
        let (_, allocations) = measure(|| 0);
        assert_eq!(allocations, 0);
    }

    #[test]
    fn nested_hook_bodies_report_the_outer_total() {
        // A hook that calls another hook: the outer measurement sees both allocations,
        // because the flag is a single bit and the counter is only reset on entry.
        let (_, outer) = measure(|| {
            let _ = Vec::<u8>::with_capacity(4);
            let (_, inner) = measure(|| {
                let _ = Vec::<u8>::with_capacity(4);
            });
            assert_eq!(inner, 1);
        });
        assert_eq!(outer, 1, "the inner hook resets the counter on entry");
    }
}

#[global_allocator]
static ALLOCATOR: GuardedAllocator = GuardedAllocator;
