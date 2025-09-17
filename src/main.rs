#![no_main]
#![no_std]

use core::mem::MaybeUninit;

use hex_slice::AsHex;
use log::info;
use uefi::{
    Identify,
    boot::SearchType,
    prelude::*,
    proto::tcg::{AlgorithmId, EventType, v2::Tcg},
};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, transmute, transmute_mut,
    transmute_ref, try_transmute_ref,
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

    const TPM_ST_NO_SESSIONS: [u8; 2] = 0x8001_u16.to_be_bytes();
    const TPM_CC_GetRandom: [u8; 4] = 0x0000017B_u32.to_be_bytes();
    const TPM_RC_SUCCESS: u32 = 0x000;

    #[repr(C)]
    #[derive(Debug, Immutable, IntoBytes, Unaligned)]
    struct CommandHeader {
        tag: [u8; 2],
        command_size: [u8; 4],
        command_code: [u8; 4],
    }

    #[repr(C)]
    #[derive(Debug, Immutable, IntoBytes)]
    struct Command<T> {
        header: CommandHeader,
        data: T,
    }

    #[repr(C)]
    #[derive(Debug, Immutable, Unaligned, FromBytes)]
    struct ResponseHeader {
        tag: [u8; 2],
        response_size: [u8; 4],
        response_code: [u8; 4],
    }

    #[derive(Debug, Immutable, Unaligned, IntoBytes)]
    #[repr(C)]
    struct GetRandomCommand {
        bytes_requested: [u8; 2],
    }

    #[derive(Debug, Immutable, KnownLayout, FromBytes)]
    #[repr(C)]
    struct GetRandomResponse {
        random_bytes: Tpm2bDigest,
    }

    #[derive(Debug, Immutable, KnownLayout, FromBytes)]
    #[repr(C)]
    struct Tpm2bDigest {
        size: [u8; 2],
        bytes: [u8; 0],
    }

    fn get_random<'a>(
        tcg: &mut Tcg,
        bytes: &'a mut [MaybeUninit<u8>],
    ) -> Result<&'a mut [u8], u32> {
        let bytes_requested =
            bytes.len() - size_of::<ResponseHeader>() - size_of::<GetRandomResponse>();
        let command: [u8; size_of::<Command<GetRandomCommand>>()] = transmute!(Command {
            header: CommandHeader {
                tag: TPM_ST_NO_SESSIONS,
                command_size: (size_of::<Command<GetRandomCommand>>() as u32).to_be_bytes(),
                command_code: TPM_CC_GetRandom,
            },
            data: GetRandomCommand {
                bytes_requested: (bytes_requested as u16).to_be_bytes(),
            },
        });
        tcg.submit_command(&command, unsafe { bytes.assume_init_mut() });
        log::debug!("Response bytes: {:?}", unsafe { bytes.assume_init_ref() });
        let response_header = <&[u8; size_of::<ResponseHeader>()]>::try_from(unsafe {
            bytes[..size_of::<ResponseHeader>()].assume_init_ref()
        })
        .unwrap();
        let response_header: &ResponseHeader = transmute_ref!(response_header);
        log::debug!("Response header: {response_header:#?}");
        let response_code = u32::from_be_bytes(response_header.response_code);
        if response_code == TPM_RC_SUCCESS {
            let response: &GetRandomResponse = transmute_ref!(
                <&[u8; size_of::<GetRandomResponse>()]>::try_from(unsafe {
                    bytes[size_of::<ResponseHeader>()
                        ..size_of::<ResponseHeader>() + size_of::<GetRandomResponse>()]
                        .assume_init_ref()
                })
                .unwrap()
            );
            let bytes_count = u16::from_be_bytes(response.random_bytes.size);
            let start = size_of::<ResponseHeader>() + size_of::<GetRandomResponse>();
            let len = bytes_count as usize;
            Ok(unsafe { bytes[start..start + len].assume_init_mut() })
        } else {
            Err(response_code)
        }
    }

    let mut buffer =
        [MaybeUninit::uninit(); size_of::<ResponseHeader>() + size_of::<GetRandomResponse>() + 4];
    let random_bytes = get_random(&mut tcg, &mut buffer);
    log::debug!("Random bytes: {:x?}", random_bytes);

    // fn send_command<I: IntoBytes + Immutable, O>(tcg: &mut Tcg, input: I) -> O
    // where
    //     [(); size_of::<CommandHeader>() + size_of::<I>()]:,
    //     [(); size_of::<ResponseHeader>() + size_of::<O>()]:,
    // {
    //     let mut command = [0u8; size_of::<CommandHeader>() + size_of::<I>()];
    //     let command_header = CommandHeader {
    //         tag: TPM_ST_NO_SESSIONS,
    //         command_size: ((size_of::<CommandHeader>() + size_of::<I>()) as u32).to_be_bytes(),
    //         command_code: TPM_CC_GetRandom,
    //     };
    //     let command_header: &[u8; size_of::<CommandHeader>()] = transmute_ref!(&command_header);
    //     (command[..size_of::<CommandHeader>()]).copy_from_slice(command_header);
    //     let command_data: &[u8; size_of::<I>()] = transmute_ref!(&input);
    //     (command[size_of::<CommandHeader>()..]).copy_from_slice(command_data);

    //     let mut output = [0u8; size_of::<ResponseHeader>() + size_of::<O>()];
    //     tcg.submit_command(&command, &mut output);

    //     todo!()
    // }

    // send_command::<_, ()>(&mut tcg, GetRandomCommand { bytes_requested: 1 });

    loop {
        boot::stall(3_000_000);
    }
    Status::SUCCESS
}
