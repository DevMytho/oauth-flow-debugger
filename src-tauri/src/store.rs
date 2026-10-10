//! In-memory store for the current run: flow config, emitted steps, and
//! security findings.
//!
//! Everything here lives only in process memory for the lifetime of the app —
//! nothing is persisted to disk, and every consumer that leaves the process
//! (the UI export) goes through `export`, which redacts secrets first.

use crate::findings::{Finding, Summary};
use crate::{FlowConfig, FlowStep};
use std::sync::{Mutex, MutexGuard};

static STEPS: Mutex<Vec<FlowStep>> = Mutex::new(Vec::new());
static FINDINGS: Mutex<Vec<Finding>> = Mutex::new(Vec::new());
static CONFIG: Mutex<Option<FlowConfig>> = Mutex::new(None);

/// Lock a static mutex, recovering from poisoning (a panic in another thread
/// must not make the whole store unusable).
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Drop everything from a previous run (called on Reset and on flow start).
pub fn reset() {
    lock(&STEPS).clear();
    lock(&FINDINGS).clear();
    *lock(&CONFIG) = None;
}

pub fn set_config(config: &FlowConfig) {
    *lock(&CONFIG) = Some(config.clone());
}

pub fn config() -> Option<FlowConfig> {
    lock(&CONFIG).clone()
}

pub fn record_step(step: &FlowStep) {
    lock(&STEPS).push(step.clone());
}

pub fn steps() -> Vec<FlowStep> {
    lock(&STEPS).clone()
}

/// Record findings, de-duplicating identical (id, detail) pairs so a retried
/// step doesn't double-count.
pub fn record_findings(new: &[Finding]) {
    let mut all = lock(&FINDINGS);
    for f in new {
        if !all.iter().any(|x| x.id == f.id && x.detail == f.detail) {
            all.push(f.clone());
        }
    }
}

pub fn findings() -> Vec<Finding> {
    lock(&FINDINGS).clone()
}

pub fn summary() -> Summary {
    Summary::from(&findings())
}
