#![no_main]
#![no_std]

use ez_tpm::{GetRandom, PcrRead, uefi::submit_command};
use hex_slice::AsHex;
use log::info;
use sha1::{Digest, Sha1};
use uefi::{
    Identify,
    boot::SearchType,
    prelude::*,
    proto::tcg::{AlgorithmId, EventType, PcrIndex, v2::Tcg},
};

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    let protocol = *boot::locate_handle_buffer(SearchType::ByProtocol(&Tcg::GUID))
        .unwrap()
        .first()
        .unwrap();
    info!("Protocol: {protocol:#?}");
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(protocol).unwrap();
    let event_log = tcg.get_event_log_v2().unwrap();
    if event_log.is_truncated() {
        panic!(
            "Event log is truncated, which means it ran out space. So we can't verify any of the events in the event log!"
        )
    }
    // Dump events
    for event in event_log.iter() {
        let event_type = event.event_type();
        let pcr_index = event.pcr_index();
        log::debug!("{event_type:?} {pcr_index:?}");
        for (algorithm, _data) in event.digests() {
            log::debug!("  {algorithm:?}");
        }
    }

    // Analyze events
    for event in event_log.iter() {
        let pcr_index = event.pcr_index();
        match event.event_type() {
            EventType::CRTM_VERSION => {
                log::debug!("Core Root of Trust for Measurement (CRTM) Version");
            }
            EventType::EFI_PLATFORM_FIRMWARE_BLOB => {
                if pcr_index.0 == 0 {
                    log::debug!("Part of Firmware");
                } else {
                    log::debug!("Part of Firmware (but {pcr_index:?} for some reason)");
                }
            }
            EventType::EFI_VARIABLE_DRIVER_CONFIG => {
                log::debug!("measure configuration for EFI Variables");
            }
            EventType::SEPARATOR => {
                log::debug!("Separator (end of code controlling the computer) {pcr_index:?}");
            }
            EventType::EFI_BOOT_SERVICES_APPLICATION => {
                let sha1 = event
                    .digests()
                    .into_iter()
                    .find_map(|(algorithm, digest)| {
                        if algorithm == AlgorithmId::SHA1 {
                            Some(digest.plain_hex(false))
                        } else {
                            None
                        }
                    })
                    .unwrap();
                log::debug!("UEFI image loaded. sha1: {sha1:x}");
            }
            EventType::EFI_ACTION => {
                let action = str::from_utf8(event.event_data()).unwrap();
                log::debug!("UEFI action: {action:?}");
            }
            event_type => {
                log::debug!("Unknown({event_type:?}) {pcr_index:?}");
            }
        }
    }

    // Replay events
    // For now we will choose SHA1 to replay
    let mut expected_sha1_pcr_values = [Default::default(); 24];
    for event in event_log.iter() {
        let digest = event
            .digests()
            .into_iter()
            .find_map(|(algorithm, digest)| {
                if algorithm == AlgorithmId::SHA1 {
                    Some(digest)
                } else {
                    None
                }
            })
            .unwrap();
        let mut hasher = Sha1::new();
        let pcr_index = event.pcr_index().0 as usize;
        hasher.update(&expected_sha1_pcr_values[pcr_index]);
        hasher.update(digest);
        expected_sha1_pcr_values[pcr_index] = hasher.finalize();
    }

    // Do TPM stuff for fun
    let mut command = GetRandom::new();
    let random_bytes = submit_command(&mut tcg, &mut command).unwrap();
    log::debug!("Random bytes: {:x?}", random_bytes);

    for i in 0..24 {
        let mut command = PcrRead::new(i);
        let pcr_value = submit_command(&mut tcg, &mut command).unwrap();
        if pcr_value.iter().all(|byte| *byte == u8::MAX) {
            log::debug!("PCR {i}: unavailable");
        } else if pcr_value == expected_sha1_pcr_values[i].as_slice() {
            let pcr_value = pcr_value.plain_hex(false);
            log::debug!("PCR {i}: {pcr_value:x} - matches event log");
        } else {
            let pcr_value = pcr_value.plain_hex(false);
            log::debug!("PCR {i}: {pcr_value:x} - does not match event log!");
        };
    }

    loop {
        boot::stall(3_000_000);
    }
    // Status::SUCCESS
}
