//! ParticleVE host and early-boot policy.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("ParticleVE requires Linux x86-64");

pub mod accounts;
pub mod admission;
pub mod bootloaders;
pub mod cli;
pub mod commission;
pub mod common;
pub mod config;
pub mod confinement;
pub mod consoles;
pub mod contracts;
pub mod coordinator;
pub mod dns;
pub mod earlyboot;
pub mod install;
pub mod inventory;
pub mod kernelruntime;
pub mod landlock;
pub mod layout;
pub mod linux;
pub mod memoryprivacy;
pub mod network;
pub mod physical;
pub mod platform;
pub mod processes;
pub mod radio;
pub mod reconfigure;
pub mod release;
pub mod reporting;
pub mod resources;
pub mod resourceusage;
pub mod security;
pub mod startup;
pub mod storage;
pub mod timesync;
pub mod versioning;
pub mod vmrun;
pub mod vms;
pub mod witness;
