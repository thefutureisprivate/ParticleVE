//! Versioned persisted-state interfaces; package versions remain provenance.
use serde_json::{Value, json};
pub fn persistent_state() -> Value {
    json!({"schema":1,"host_state":"particleve-host-state-v3","system_ca":"fedora-shared-volatile-v1","storage_admission":"uefi-witness-v1","bootloaders":"independent-efi-trial-v1","boot_console":"signed-uki-console-profiles-v1","btrfs":"native-raid1-no-feature-upgrades-v1","vm_labels":"confined-mcs-pair-v1","vm_unit":"bounded-native-vmspawn-v2","vm_disk":"raw-nocow-v1","vm_efi":"ovmf-qcow2-no-conversion-v1","vm_tpm":"swtpm-tpm2-no-conversion-v1"})
}
