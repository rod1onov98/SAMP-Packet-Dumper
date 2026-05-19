#pragma once
#include <cstdint>

enum PacketID : uint8_t {
    ID_INTERNAL_PING = 6,
    ID_PING = 7,
    ID_PING_OPEN_CONNECTIONS = 8,
    ID_CONNECTED_PONG = 9,
    ID_REQUEST_STATIC_DATA = 10,
    ID_CONNECTION_REQUEST = 11,
    ID_AUTH_KEY = 12,
    ID_BROADCAST_PINGS = 14,
    ID_SECURED_CONNECTION_RESPONSE = 15,
    ID_SECURED_CONNECTION_CONFIRMATION = 16,
    ID_RPC_MAPPING = 17,
    ID_SET_RANDOM_NUMBER_SEED = 19,
    ID_RPC = 20,
    ID_RPC_REPLY = 21,
    ID_DETECT_LOST_CONNECTIONS = 23,
    ID_OPEN_CONNECTION_REQUEST = 24,
    ID_OPEN_CONNECTION_REPLY = 25,
    ID_OPEN_CONNECTION_COOKIE = 26,
    ID_RSA_PUBLIC_KEY_MISMATCH = 28,
    ID_CONNECTION_ATTEMPT_FAILED = 29,
    ID_NEW_INCOMING_CONNECTION = 30,
    ID_NO_FREE_INCOMING_CONNECTIONS = 31,
    ID_DISCONNECTION_NOTIFICATION = 32,
    ID_CONNECTION_LOST = 33,
    ID_CONNECTION_REQUEST_ACCEPTED = 34,
    ID_CONNECTION_BANNED = 36,
    ID_INVALID_PASS = 37,
    ID_MODIFIED_PACKET = 38,
    ID_PONG = 39,
    ID_TIMESTAMP = 40,
    ID_RECEIVED_STATIC_DATA = 41,
    ID_REMOTE_DISCONNECTION_NOTIFICATION = 42,
    ID_REMOTE_CONNECTION_LOST = 43,
    ID_REMOTE_NEW_INCOMING_CONNECTION = 44,
    ID_REMOTE_EXISTING_CONNECTION = 45,
    ID_REMOTE_STATIC_DATA = 46,
    ID_ADVERTISE_SYSTEM = 55,

    // samp sync packets
    ID_DRIVER_SYNC = 200,
    ID_RCON_COMMAND = 201,
    ID_RCON_RESPONSE = 202,
    ID_AIM_SYNC = 203,
    ID_WEAPONS_UPDATE = 204,
    ID_STATS_UPDATE = 205,
    ID_BULLET_SYNC = 206,
    ID_ONFOOT_SYNC = 207,
    ID_VEHICLE_SYNC = 208,  
    ID_UNOCCUPIED_SYNC = 209,
    ID_TRAILER_SYNC = 210,
    ID_PASSENGER_SYNC = 211,
    ID_SPECTATOR_SYNC = 212,
    ID_USER_INTERFACE_SYNC = 252, // custom packet, does not exist in default samp
};

// rpc ids

enum RpcID : uint8_t {
    RPC_SetPlayerName = 11,
    RPC_SetPlayerPos = 12,
    RPC_SetPlayerPosFindZ = 13,
    RPC_SetPlayerHealth = 14,
    RPC_TogglePlayerControllable = 15,
    RPC_PlaySound = 16,
    RPC_HaveSomeMoney = 18,
    RPC_SetPlayerFacingAngle = 19,
    RPC_ResetMoney = 20,
    RPC_ResetPlayerWeapons = 21,
    RPC_GivePlayerWeapon = 22,
    RPC_ClickPlayer = 23,
    RPC_SetVehicleParamsEx = 24,
    RPC_ClientJoin = 25,
    RPC_EnterVehicle = 26,
    RPC_SelectObject = 27,
    RPC_CancelEdit = 28,
    RPC_SetPlayerDrunkLevel = 35,
    RPC_Create3DTextLabel = 36,
    RPC_DisableCheckpoint = 37,
    RPC_SetRaceCheckpoint = 38,
    RPC_DisableRaceCheckpoint = 39,
    RPC_PlayAudioStream = 41,
    RPC_StopAudioStream = 42,
    RPC_CreateObject = 44,
    RPC_SetObjectPos = 45,
    RPC_SetObjectRotation = 46,
    RPC_DestroyObject = 47,
    RPC_ServerCommand = 50,
    RPC_Spawn = 52,
    RPC_Death = 53,
    RPC_NPCJoin = 54,
    RPC_MapIcon = 56,
    RPC_RemoveComponent = 57,
    RPC_Destroy3DTextLabel = 58,
    RPC_DialogResponse = 62,
    RPC_DestroyPickup = 63,
    RPC_LinkVehicle = 65,
    RPC_SetPlayerArmour = 66,
    RPC_SetArmedWeapon = 67,
    RPC_SetSpawnInfo = 68,
    RPC_PutPlayerInVehicle = 70,
    RPC_RemovePlayerFromVehicle = 71,
    RPC_SetPlayerColor = 72,
    RPC_DisplayGameText = 73,
    RPC_AttachObjectToPlayer = 75,
    RPC_InterpolateCamera = 82,
    RPC_ClickTextDraw = 83,
    RPC_SetObjectMaterial = 84,
    RPC_StopFlashGangZone = 85,
    RPC_ApplyAnimation = 86,
    RPC_ClearAnimations = 87,
    RPC_SetSpecialAction = 88,
    RPC_SetFightingStyle = 89,
    RPC_SetPlayerVelocity = 90,
    RPC_SetVehicleVelocity = 91,
    RPC_ClientMessage = 93,
    RPC_WorldTime = 94,
    RPC_Pickup = 95,
    RPC_ScmEvent = 96,
    RPC_DestroyWeaponPickup = 97,
    RPC_MoveObject = 99,
    RPC_Chat = 101,
    RPC_EditTextDraw = 105,
    RPC_DamageVehicle = 106,
    RPC_SetCheckpoint = 107,
    RPC_AddGangZone = 108,
    RPC_SetPlayerAttachedObject = 113,
    RPC_PlayerGiveTakeDamage = 115,
    RPC_EditObject = 117,
    RPC_SetInteriorId = 118,
    RPC_MapMarker = 119,
    RPC_RemoveGangZone = 120,
    RPC_FlashGangZone = 121,
    RPC_StopObject = 122,
    RPC_NumberPlate = 123,
    RPC_TogglePlayerSpectating = 124,
    RPC_PlayerSpectatePlayer = 126,
    RPC_PlayerSpectateVehicle = 127,
    RPC_RequestClass = 128,
    RPC_RequestSpawn = 129,
    RPC_ConnectionRejected = 130,
    RPC_PickedUpPickup = 131,
    RPC_SetPlayerWantedLevel = 133,
    RPC_ShowTextDraw = 134,
    RPC_HideTextDraw = 135,
    RPC_VehicleDestroyed = 136,
    RPC_ServerJoin = 137,
    RPC_ServerQuit = 138,
    RPC_InitGame = 139,
    RPC_SetWeaponAmmo = 145,
    RPC_SetVehicleHealth = 147,
    RPC_AttachTrailerToVehicle = 148,
    RPC_DetachTrailerFromVehicle = 149,
    RPC_Weather = 152,
    RPC_SetPlayerSkin = 153,
    RPC_ExitVehicle = 154,
    RPC_UpdateScoresPingsIPs = 155,
    RPC_SetInterior = 156,
    RPC_SetCameraPos = 157,
    RPC_SetCameraLookAt = 158,
    RPC_SetVehiclePos = 159,
    RPC_SetVehicleZAngle = 160,
    RPC_VehicleParams = 161,
    RPC_SetCameraBehindPlayer = 162,
    RPC_WorldPlayerRemove = 163,
    RPC_WorldVehicleAdd = 164,
    RPC_WorldVehicleRemove = 165,
    RPC_WorldPlayerDeath = 166,
    RPC_WorldActorAdd = 171,
    RPC_WorldActorRemove = 172,
    RPC_ApplyActorAnimation = 173,
    RPC_ClearActorAnimations = 174,
    RPC_SetActorFacingAngle = 175,
    RPC_SetActorPos = 176,
    RPC_ActorGiveDamage = 177,
    RPC_SetActorHealth = 178,
    RPC_WorldPlayerAdd = 32,
    RPC_SetPlayerSkillLevel = 34,
    RPC_DialogBox = 61,
    RPC_AttachCameraToObject = 81,
    RPC_ShowNameTag = 80,
    RPC_CreateExplosion = 79,
    RPC_DisableMapIcon = 144,
    RPC_PickedUpWeapon = 255,
};

//  reliability

enum PacketReliability : uint8_t {
    UNRELIABLE = 6,
    UNRELIABLE_SEQUENCED = 7,
    RELIABLE = 8,
    RELIABLE_ORDERED = 9,
    RELIABLE_SEQUENCED = 10,
};

//  sync structs (plain layout, filled by parser)

struct OnFootSync {
    uint16_t lrKey;
    uint16_t udKey;
    uint16_t keys;
    float    x, y, z;
    float    quatW, quatX, quatY, quatZ;
    uint8_t  health;
    uint8_t  armour;
    uint8_t  additionalKey;   // 2 bits
    uint8_t  weaponId;        // 6 bits
    uint8_t  specialAction;
    float    velX, velY, velZ;
    float    surfOffX, surfOffY, surfOffZ;
    uint16_t surfVehicleId;
    int16_t  animationId;
    int16_t  animationFlags;
};

struct DriverSync {
    uint16_t vehicleId;
    uint16_t lrKey;
    uint16_t udKey;
    uint16_t keys;
    float    quatW, quatX, quatY, quatZ;
    float    x, y, z;
    float    velX, velY, velZ;
    float    vehicleHealth;
    uint8_t  playerHealth;
    uint8_t  playerArmour;
    uint8_t  additionalKey;   // 2 bits
    uint8_t  weaponId;        // 6 bits
    uint8_t  sirenState;
    uint8_t  landingGearState;
    uint16_t trailerId;
    float    trainSpeed;      // also bike incline or hydra thrust
};

struct AimSync {
    uint8_t camMode;
    float   camFrontX, camFrontY, camFrontZ;
    float   camPosX, camPosY, camPosZ;
    float   aimZ;
    uint8_t weaponState;  // 2 bits
    uint8_t camZoom;      // 6 bits
    uint8_t aspectRatio;
};

struct BulletSync {
    uint8_t  hitType;
    uint16_t hitId;
    float    originX, originY, originZ;
    float    hitPosX, hitPosY, hitPosZ;
    float    offsetX, offsetY, offsetZ;
    uint8_t  weaponId;
};

struct WeaponsUpdate {
    uint16_t targetPlayer;
    uint16_t targetActor;
    struct Slot {
        uint8_t  slot;
        uint8_t  weapon;
        uint16_t ammo;
    } slots[12];
};

struct StatsUpdate {
    int32_t money;
    int32_t drunkLevel;
};

struct UnoccupiedSync {
    uint16_t vehicleId;
    uint8_t  seatId;
    float    rollX, rollY, rollZ;
    float    dirX, dirY, dirZ;
    float    x, y, z;
    float    angVelX, angVelY, angVelZ;
    float    vehicleHealth;
};

struct TrailerSync {
    uint16_t trailerId;
    float    x, y, z;
    float    quatX, quatY, quatZ;
    float    velX, velY, velZ;
    float    angVelX, angVelY, angVelZ;
};

struct PassengerSync {
    uint16_t vehicleId;
    uint8_t  driveBy;    // 2 bits
    uint8_t  seatId;     // 6 bits
    uint8_t  additionalKey; // 2 bits
    uint8_t  weaponId;   // 6 bits
    uint8_t  health;
    uint8_t  armour;
    uint16_t lrKey;
    uint16_t udKey;
    uint16_t keys;
    float    x, y, z;
};

struct SpectatorSync {
    uint16_t lrKey;
    uint16_t udKey;
    uint16_t keys;
    float    x, y, z;
};

struct RconCommand {
    uint32_t textLength;
    char     cmdText[256];
};