#ifndef __AIRPLAY__
#define __AIRPLAY__

//AIRPLAY MDNS FEATURES
#define AIRPLAY_FEATURE_VIDEO 0x1 //video supported
#define AIRPLAY_FEATURE_PHOTO 0x2 //photo supported
#define AIRPLAY_FEATURE_VIDEO_FAIRPLAY 0x4 //video protected with FairPlay DRM
#define AIRPLAY_FEATURE_VIDEO_VOLUME_CONTROL 0x8 //volume control supported for videos
#define AIRPLAY_FEATURE_VIDEO_HTTP_LIVESTREAMS 0x10 //http live streaming supported
#define AIRPLAY_FEATURE_SLIDESHOW 0x20 //slideshow supported
#define AIRPLAY_FEATURE_SCREEN 0x80 //mirroring supported
#define AIRPLAY_FEATURE_SCREEN_ROTATE 0x100 //screen rotation supported
#define AIRPLAY_FEATURE_AUDIO 0x200 //audio supported
#define AIRPLAY_FEATURE_AUDIO_REDUNDANT 0x800 //audio packet redundancy supported
#define AIRPLAY_FEATURE_FPSAP_V2_PT5_AES_GCM 0x1000 //FairPlay secure auth supported
#define AIRPLAY_FEATURE_PHOTO_CACHING 0x2000 //photo preloading supported
#define AIRPLAY_FEATURE_AUTHENTICATION_4 0x4000 //Authentication type 4. FairPlay authentication
#define AIRPLAY_FEATURE_METADATA_FEATURE_1 0x8000 //bit 1 of MetadataFeatures. Artwork.
#define AIRPLAY_FEATURE_METADATA_FEATURE_2 0x10000 //bit 2 of MetadataFeatures. Progress.
#define AIRPLAY_FEATURE_METADATA_FEATURE_0 0x20000 //bit 0 of MetadataFeatures. Text.
#define AIRPLAY_FEATURE_AUDIOFORMAT_1 0x40000 //support for audio format 1
#define AIRPLAY_FEATURE_AUDIOFORMAT_2 0x80000 //support for audio format 2. This bit must be set for AirPlay 2 connection to work
#define AIRPLAY_FEATURE_AUDIOFORMAT_3 0x100000 //support for audio format 3. This bit must be set for AirPlay 2 connection to work
#define AIRPLAY_FEATURE_AUDIOFORMAT_4 0x200000 //support for audio format 4
#define AIRPLAY_FEATURE_AUTHENTICATION_1 0x800000 //Authentication type 1. RSA Authentication
#define AIRPLAY_FEATURE_HAS_UNIFIED_ADVERTISER_INFO 0x4000000 //No desc
#define AIRPLAY_FEATURE_SUPPORTS_LEGACY_PAIRING 0x8000000 //No desc
#define AIRPLAY_FEATURE_RAOP 0x40000000 //RAOP is supported on this port. With this bit set your don't need the AirTunes service
#define AIRPLAY_FEATURE_IS_CARPLAY_OR_SUPPORTSVOLUME 0x1 //Don’t read key from pk record it is known
#define AIRPLAY_FEATURE_SUPPORTS_AIRPLAY_VIDEO_PLAYQUEUE 0x2 //No desc
#define AIRPLAY_FEATURE_SUPPORTS_AIRPLAY_FROM_CLOUD 0x4 //No desc
#define AIRPLAY_FEATURE_SUPPORTS_CORE_UTILS_PAIRING_AND_ENCRYPTION 0x40 //SupportsHKPairingAndAccessControl, SupportsSystemPairing and SupportsTransientPairing implies SupportsCoreUtilsPairingAndEncryption
#define AIRPLAY_FEATURE_SUPPORTS_BUFFERED_AUDIO 0x100 //Bit needed for device to show as supporting multi-room audio
#define AIRPLAY_FEATURE_SUPPORTS_PTP 0x200 //Bit needed for device to show as supporting multi-room audio
#define AIRPLAY_FEATURE_SUPPORTS_SCREEN_MULTICODEC 0x400 //No desc
#define AIRPLAY_FEATURE_SUPPORTS_SYSTEM_PAIRING 0x800 //No desc
#define AIRPLAY_FEATURE_SUPPORTS_HK_PAIRING_AND_ACCESSCONTROL 0x4000 //No desc
#define AIRPLAY_FEATURE_SUPPORTS_TRANSIENT_PAIRING 0x10000 //SupportsSystemPairing implies SupportsTransientPairing
#define AIRPLAY_FEATURE_METADATA_FEATURE_4 0x40000 //bit 4 of MetadataFeatures. binary plist.
#define AIRPLAY_FEATURE_SUPPORTS_UNIFIED_PAIR_SETUP_AND_MFI 0x80000 //Authentication type 8. MFi authentication
#define AIRPLAY_FEATURE_SUPPORTS_SET_PEERS_EXTENDED_MESSAGE 0x100000 //No desc

//AIRPLAY STATUS FLAGS
#define AIRPLAY_STATUS_PROBLEM_DETECTED 0x1 //Defined in CarPlay section of MFi spec. Not seen set anywhere
#define AIRPLAY_STATUS_DEVICE_NOTCONFIGURED 0x2 //Defined in CarPlay section of MFi spec. Not seen set anywhere
#define AIRPLAY_STATUS_AUDIO_CABLE_ATTACHED 0x4 //Defined in CarPlay section of MFi spec. Seen on AppleTV, Denon AVR, HomePod, Airport Express
#define AIRPLAY_STATUS_PIN_REQUIRED 0x8 //No desc
#define AIRPLAY_STATUS_SUPPORTS_AIRPLAY_FROM_CLOUD 0x40 //No desc
#define AIRPLAY_STATUS_PASSWORD_REQUIRED 0x80 //No desc
#define AIRPLAY_STATUS_ONETIME_PAIRING_REQUIRED 0x200 //No desc
#define AIRPLAY_STATUS_DEVICE_SETUP_FOR_HKACCESSCONTROL 0x400 //No desc
#define AIRPLAY_STATUS_DEVICE_SUPPORTS_RELAY 0x800 //Shows in logs as relayable. When set iOS will connect to the device to get currently playing track.
#define AIRPLAY_STATUS_SILENT_PRIMARY 0x1000 //No desc
#define AIRPLAY_STATUS_TIGHTSYNC_GROUP_LEADER 0x2000 //No desc
#define AIRPLAY_STATUS_TIGHTSYNC_BUDDY_NOTREACHABLE 0x4000 //No desc
#define AIRPLAY_STATUS_APPLEMUSIC_SUBSCRIBER 0x8000 //Shows in logs as music
#define AIRPLAY_STATUS_CLOUD_LIBRARY_ON 0x10000 //Shows in logs as iCML
#define AIRPLAY_STATUS_RECEIVER_SESSION_ACTIVE 0x20000 //Shows in logs as airplay-receiving. Set when Apple TV is receiving anything via AirPlay.

#endif