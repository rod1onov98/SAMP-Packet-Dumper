#include "samp_parser.hpp"
#include "raknet/BitStream.h"
#include "raknet/DS_RangeList.h"
#include <cstdio>
#include <cstring>

const char* packet_id_name(uint8_t id) {
    switch (static_cast<PacketID>(id)) {
    case ID_INTERNAL_PING:                    return "INTERNAL_PING";
    case ID_PING:                             return "PING";
    case ID_PING_OPEN_CONNECTIONS:            return "PING_OPEN_CONNECTIONS";
    case ID_CONNECTED_PONG:                   return "CONNECTED_PONG";
    case ID_CONNECTION_REQUEST:               return "CONNECTION_REQUEST";
    case ID_AUTH_KEY:                         return "AUTH_KEY";
    case ID_RPC_MAPPING:                      return "RPC_MAPPING";
    case ID_SET_RANDOM_NUMBER_SEED:           return "SET_RANDOM_NUMBER_SEED";
    case ID_RPC:                              return "RPC";
    case ID_RPC_REPLY:                        return "RPC_REPLY";
    case ID_DETECT_LOST_CONNECTIONS:          return "DETECT_LOST_CONNECTIONS";
    case ID_OPEN_CONNECTION_REQUEST:          return "OPEN_CONNECTION_REQUEST";
    case ID_OPEN_CONNECTION_REPLY:            return "OPEN_CONNECTION_REPLY";
    case ID_OPEN_CONNECTION_COOKIE:           return "OPEN_CONNECTION_COOKIE";
    case ID_NEW_INCOMING_CONNECTION:          return "NEW_INCOMING_CONNECTION";
    case ID_NO_FREE_INCOMING_CONNECTIONS:     return "NO_FREE_INCOMING_CONNECTIONS";
    case ID_DISCONNECTION_NOTIFICATION:       return "DISCONNECTION_NOTIFICATION";
    case ID_CONNECTION_LOST:                  return "CONNECTION_LOST";
    case ID_CONNECTION_REQUEST_ACCEPTED:      return "CONNECTION_REQUEST_ACCEPTED";
    case ID_CONNECTION_BANNED:                return "CONNECTION_BANNED";
    case ID_DRIVER_SYNC:                      return "DRIVER_SYNC";
    case ID_RCON_COMMAND:                     return "RCON_COMMAND";
    case ID_RCON_RESPONSE:                    return "RCON_RESPONSE";
    case ID_AIM_SYNC:                         return "AIM_SYNC";
    case ID_WEAPONS_UPDATE:                   return "WEAPONS_UPDATE";
    case ID_STATS_UPDATE:                     return "STATS_UPDATE";
    case ID_BULLET_SYNC:                      return "BULLET_SYNC";
    case ID_ONFOOT_SYNC:                      return "ONFOOT_SYNC";
    case ID_UNOCCUPIED_SYNC:                  return "UNOCCUPIED_SYNC";
    case ID_TRAILER_SYNC:                     return "TRAILER_SYNC";
    case ID_PASSENGER_SYNC:                   return "PASSENGER_SYNC";
    case ID_SPECTATOR_SYNC:                   return "SPECTATOR_SYNC";
    case ID_USER_INTERFACE_SYNC:              return "USER_INTERFACE_SYNC";
    default:                                  return "UNKNOWN";
    }
}

const char* rpc_id_name(uint8_t id) {
    switch (static_cast<RpcID>(id)) {
    case RPC_ClientJoin:            return "ClientJoin";
    case RPC_ServerJoin:            return "ServerJoin";
    case RPC_ServerQuit:            return "ServerQuit";
    case RPC_InitGame:              return "InitGame";
    case RPC_Death:                 return "Death";
    case RPC_RequestClass:          return "RequestClass";
    case RPC_RequestSpawn:          return "RequestSpawn";
    case RPC_Spawn:                 return "Spawn";
    case RPC_Chat:                  return "Chat";
    case RPC_EnterVehicle:          return "EnterVehicle";
    case RPC_ExitVehicle:           return "ExitVehicle";
    case RPC_DialogResponse:        return "DialogResponse";
    case RPC_DialogBox:             return "DialogBox";
    case RPC_ClientMessage:         return "ClientMessage";
    case RPC_WorldPlayerAdd:        return "WorldPlayerAdd";
    case RPC_WorldPlayerDeath:      return "WorldPlayerDeath";
    case RPC_WorldPlayerRemove:     return "WorldPlayerRemove";
    case RPC_WorldVehicleAdd:       return "WorldVehicleAdd";
    case RPC_WorldVehicleRemove:    return "WorldVehicleRemove";
    case RPC_SetCheckpoint:         return "SetCheckpoint";
    case RPC_SetPlayerHealth:       return "SetPlayerHealth";
    case RPC_SetPlayerArmour:       return "SetPlayerArmour";
    case RPC_SetPlayerPos:          return "SetPlayerPos";
    case RPC_SetPlayerName:         return "SetPlayerName";
    case RPC_SetPlayerColor:        return "SetPlayerColor";
    case RPC_SetPlayerSkin:         return "SetPlayerSkin";
    case RPC_Weather:               return "Weather";
    case RPC_WorldTime:             return "WorldTime";
    case RPC_ConnectionRejected:    return "ConnectionRejected";
    case RPC_MapMarker:             return "MapMarker";
    case RPC_GivePlayerWeapon:      return "GivePlayerWeapon";
    case RPC_ShowTextDraw:          return "ShowTextDraw";
    case RPC_HideTextDraw:          return "HideTextDraw";
    case RPC_PlayerGiveTakeDamage:  return "PlayerGiveTakeDamage";
    default:                        return "UNKNOWN";
    }
}

const char* reliability_name(uint8_t rel) {
    switch (static_cast<PacketReliability>(rel)) {
    case UNRELIABLE:           return "UNRELIABLE";
    case UNRELIABLE_SEQUENCED: return "UNRELIABLE_SEQ";
    case RELIABLE:             return "RELIABLE";
    case RELIABLE_ORDERED:     return "RELIABLE_ORD";
    case RELIABLE_SEQUENCED:   return "RELIABLE_SEQ";
    default:                   return "UNKNOWN";
    }
}

bool parse_onfoot_sync(RakNet::BitStream& bs, OnFootSync& s) {
    bs.Read(s.lrKey);
    bs.Read(s.udKey);
    bs.Read(s.keys);
    bs.Read(s.x);
    bs.Read(s.y);
    bs.Read(s.z);
    bs.Read(s.quatW);
    bs.Read(s.quatX);
    bs.Read(s.quatY);
    bs.Read(s.quatZ);
    bs.Read(s.health);
    bs.Read(s.armour);

    uint8_t packed = 0;
    bs.ReadBits(&packed, 8, true);
    s.additionalKey = (packed >> 6) & 0x03;
    s.weaponId = packed & 0x3F;

    bs.Read(s.specialAction);
    bs.Read(s.velX);
    bs.Read(s.velY);
    bs.Read(s.velZ);
    bs.Read(s.surfOffX);
    bs.Read(s.surfOffY);
    bs.Read(s.surfOffZ);
    bs.Read(s.surfVehicleId);
    bs.Read(s.animationId);
    bs.Read(s.animationFlags);

    printf("[ONFOOT_SYNC]\n");
    printf("pos       : (%.3f, %.3f, %.3f)\n", s.x, s.y, s.z);
    printf("quat      : (%.3f, %.3f, %.3f, %.3f)\n", s.quatW, s.quatX, s.quatY, s.quatZ);
    printf("hp/armour : %d / %d\n", s.health, s.armour);
    printf("weapon    : %d  special_action: %d\n", s.weaponId, s.specialAction);
    printf("velocity  : (%.3f, %.3f, %.3f)\n", s.velX, s.velY, s.velZ);
    printf("surf_off  : (%.3f, %.3f, %.3f) veh=%d\n", s.surfOffX, s.surfOffY, s.surfOffZ, s.surfVehicleId);
    printf("anim      : id=%d flags=%d\n", s.animationId, s.animationFlags);
    printf("keys      : lr=%u ud=%u k=%u add=%u\n", s.lrKey, s.udKey, s.keys, s.additionalKey);
    return true;
}

bool parse_driver_sync(RakNet::BitStream& bs, DriverSync& s) {
    bs.Read(s.vehicleId);
    bs.Read(s.lrKey);
    bs.Read(s.udKey);
    bs.Read(s.keys);
    bs.Read(s.quatW);
    bs.Read(s.quatX);
    bs.Read(s.quatY);
    bs.Read(s.quatZ);
    bs.Read(s.x);
    bs.Read(s.y);
    bs.Read(s.z);
    bs.Read(s.velX);
    bs.Read(s.velY);
    bs.Read(s.velZ);
    bs.Read(s.vehicleHealth);
    bs.Read(s.playerHealth);
    bs.Read(s.playerArmour);

    uint8_t packed = 0;
    bs.ReadBits(&packed, 8, true);
    s.additionalKey = (packed >> 6) & 0x03;
    s.weaponId = packed & 0x3F;

    bs.Read(s.sirenState);
    bs.Read(s.landingGearState);
    bs.Read(s.trailerId);
    bs.Read(s.trainSpeed);

    printf("[DRIVER_SYNC]\n");
    printf("vehicle   : %d\n", s.vehicleId);
    printf("pos       : (%.3f, %.3f, %.3f)\n", s.x, s.y, s.z);
    printf("quat      : (%.3f, %.3f, %.3f, %.3f)\n", s.quatW, s.quatX, s.quatY, s.quatZ);
    printf("velocity  : (%.3f, %.3f, %.3f)\n", s.velX, s.velY, s.velZ);
    printf("veh_hp    : %.1f  player: %d/%d\n", s.vehicleHealth, s.playerHealth, s.playerArmour);
    printf("weapon    : %d  siren=%d gear=%d\n", s.weaponId, s.sirenState, s.landingGearState);
    printf("trailer   : %d  train_speed/bike_inc: %.3f\n", s.trailerId, s.trainSpeed);
    printf("keys      : lr=%u ud=%u k=%u add=%u\n", s.lrKey, s.udKey, s.keys, s.additionalKey);
    return true;
}

bool parse_aim_sync(RakNet::BitStream& bs, AimSync& s) {
    bs.Read(s.camMode);
    bs.Read(s.camFrontX);
    bs.Read(s.camFrontY);
    bs.Read(s.camFrontZ);
    bs.Read(s.camPosX);
    bs.Read(s.camPosY);
    bs.Read(s.camPosZ);
    bs.Read(s.aimZ);

    uint8_t packed = 0;
    bs.ReadBits(&packed, 8, true);
    s.weaponState = (packed >> 6) & 0x03;
    s.camZoom = packed & 0x3F;

    bs.Read(s.aspectRatio);

    printf("[AIM_SYNC]\n");
    printf("cam_mode  : %d  zoom=%d  aspect=%.3f\n", s.camMode, s.camZoom, s.aspectRatio / 255.0f);
    printf("cam_front : (%.3f, %.3f, %.3f)\n", s.camFrontX, s.camFrontY, s.camFrontZ);
    printf("cam_pos   : (%.3f, %.3f, %.3f)\n", s.camPosX, s.camPosY, s.camPosZ);
    printf("aim_z     : %.3f  weapon_state=%d\n", s.aimZ, s.weaponState);
    return true;
}

bool parse_bullet_sync(RakNet::BitStream& bs, BulletSync& s) {
    bs.Read(s.hitType);
    bs.Read(s.hitId);
    bs.Read(s.originX);
    bs.Read(s.originY);
    bs.Read(s.originZ);
    bs.Read(s.hitPosX);
    bs.Read(s.hitPosY);
    bs.Read(s.hitPosZ);
    bs.Read(s.offsetX);
    bs.Read(s.offsetY);
    bs.Read(s.offsetZ);
    bs.Read(s.weaponId);

    static const char* hitTypes[] = { "nothing", "player", "vehicle", "object", "self" };
    const char* hitName = (s.hitType < 5) ? hitTypes[s.hitType] : "unknown";

    printf("[BULLET_SYNC]\n");
    printf("weapon    : %d  hit_type=%d (%s)  hit_id=%d\n", s.weaponId, s.hitType, hitName, s.hitId);
    printf("origin    : (%.3f, %.3f, %.3f)\n", s.originX, s.originY, s.originZ);
    printf("hit_pos   : (%.3f, %.3f, %.3f)\n", s.hitPosX, s.hitPosY, s.hitPosZ);
    printf("offset    : (%.3f, %.3f, %.3f)\n", s.offsetX, s.offsetY, s.offsetZ);
    return true;
}

bool parse_weapons_update(RakNet::BitStream& bs, WeaponsUpdate& s) {
    bs.Read(s.targetPlayer);
    bs.Read(s.targetActor);

    printf("  [WEAPONS_UPDATE]  target_player=%d  target_actor=%d\n", s.targetPlayer, s.targetActor);

    for (int i = 0; i < 12; i++) {
        bs.Read(s.slots[i].slot);
        bs.Read(s.slots[i].weapon);
        bs.Read(s.slots[i].ammo);
        if (s.slots[i].weapon != 0)
            printf("    slot[%2d] weapon=%3d  ammo=%d\n", s.slots[i].slot, s.slots[i].weapon, s.slots[i].ammo);
    }
    return true;
}

bool parse_stats_update(RakNet::BitStream& bs, StatsUpdate& s) {
    bs.Read(s.money);
    bs.Read(s.drunkLevel);
    printf("[STATS_UPDATE]  money=%d  drunk=%d\n", s.money, s.drunkLevel);
    return true;
}

bool parse_unoccupied_sync(RakNet::BitStream& bs, UnoccupiedSync& s) {
    bs.Read(s.vehicleId);
    bs.Read(s.seatId);
    bs.Read(s.rollX);  bs.Read(s.rollY);  bs.Read(s.rollZ);
    bs.Read(s.dirX);   bs.Read(s.dirY);   bs.Read(s.dirZ);
    bs.Read(s.x);      bs.Read(s.y);      bs.Read(s.z);
    bs.Read(s.angVelX); bs.Read(s.angVelY); bs.Read(s.angVelZ);
    bs.Read(s.vehicleHealth);

    printf("[UNOCCUPIED_SYNC]\n");
    printf("vehicle   : %d  seat=%d\n", s.vehicleId, s.seatId);
    printf("pos       : (%.3f, %.3f, %.3f)\n", s.x, s.y, s.z);
    printf("roll      : (%.3f, %.3f, %.3f)\n", s.rollX, s.rollY, s.rollZ);
    printf("direction : (%.3f, %.3f, %.3f)\n", s.dirX, s.dirY, s.dirZ);
    printf("ang_vel   : (%.3f, %.3f, %.3f)\n", s.angVelX, s.angVelY, s.angVelZ);
    printf("veh_hp    : %.1f\n", s.vehicleHealth);
    return true;
}

bool parse_trailer_sync(RakNet::BitStream& bs, TrailerSync& s) {
    bs.Read(s.trailerId);
    bs.Read(s.x);    bs.Read(s.y);    bs.Read(s.z);
    bs.Read(s.quatX); bs.Read(s.quatY); bs.Read(s.quatZ);
    bs.Read(s.velX);  bs.Read(s.velY);  bs.Read(s.velZ);
    bs.Read(s.angVelX); bs.Read(s.angVelY); bs.Read(s.angVelZ);

    printf("[TRAILER_SYNC]\n");
    printf("trailer   : %d\n", s.trailerId);
    printf("pos       : (%.3f, %.3f, %.3f)\n", s.x, s.y, s.z);
    printf("quat      : (%.3f, %.3f, %.3f)\n", s.quatX, s.quatY, s.quatZ);
    printf("velocity  : (%.3f, %.3f, %.3f)\n", s.velX, s.velY, s.velZ);
    printf("ang_vel   : (%.3f, %.3f, %.3f)\n", s.angVelX, s.angVelY, s.angVelZ);
    return true;
}

bool parse_passenger_sync(RakNet::BitStream& bs, PassengerSync& s) {
    bs.Read(s.vehicleId);

    uint8_t packed1 = 0, packed2 = 0;
    bs.ReadBits(&packed1, 8, true);
    s.driveBy = (packed1 >> 6) & 0x03;
    s.seatId = packed1 & 0x3F;

    bs.ReadBits(&packed2, 8, true);
    s.additionalKey = (packed2 >> 6) & 0x03;
    s.weaponId = packed2 & 0x3F;

    bs.Read(s.health);
    bs.Read(s.armour);
    bs.Read(s.lrKey);
    bs.Read(s.udKey);
    bs.Read(s.keys);
    bs.Read(s.x);
    bs.Read(s.y);
    bs.Read(s.z);

    printf("[PASSENGER_SYNC]\n");
    printf("vehicle   : %d  seat=%d  drive_by=%d\n", s.vehicleId, s.seatId, s.driveBy);
    printf("pos       : (%.3f, %.3f, %.3f)\n", s.x, s.y, s.z);
    printf("hp/armour : %d / %d\n", s.health, s.armour);
    printf("weapon    : %d\n", s.weaponId);
    printf("keys      : lr=%u ud=%u k=%u\n", s.lrKey, s.udKey, s.keys);
    return true;
}

bool parse_spectator_sync(RakNet::BitStream& bs, SpectatorSync& s) {
    bs.Read(s.lrKey);
    bs.Read(s.udKey);
    bs.Read(s.keys);
    bs.Read(s.x);
    bs.Read(s.y);
    bs.Read(s.z);

    printf("[SPECTATOR_SYNC]\n");
    printf("pos  : (%.3f, %.3f, %.3f)\n", s.x, s.y, s.z);
    printf("keys : lr=%u ud=%u k=%u\n", s.lrKey, s.udKey, s.keys);
    return true;
}

bool parse_rcon_command(RakNet::BitStream& bs, RconCommand& s) {
    bs.Read(s.textLength);
    s.textLength = (s.textLength < sizeof(s.cmdText) - 1) ? s.textLength : sizeof(s.cmdText) - 1;
    memset(s.cmdText, 0, sizeof(s.cmdText));
    if (s.textLength > 0)
        bs.Read(s.cmdText, s.textLength);

    printf("[RCON_COMMAND]  len=%u  cmd=\"%s\"\n", s.textLength, s.cmdText);
    return true;
}


static void log_hex_line(const uint8_t* data, int len) {
    for (int i = 0; i < len && i < 32; i++)
        printf("%02X ", data[i]);
    if (len > 32) printf("... (%d bytes total)", len);
    printf("\n");
}

static void dispatch_packet(uint8_t packetId, RakNet::BitStream& bs, Direction dir, uint16_t seqId) {
    const char* dir_str = (dir == Direction::ClientToServer) ? "C->S" : "S->C";

    printf("[%s] seqid=%-5u  pkt=%3d (%s)\n", dir_str, seqId, packetId, packet_id_name(packetId));

    switch (static_cast<PacketID>(packetId)) {
    case ID_RPC: {
        uint8_t rpcId = 0;
        bs.Read(rpcId);
        uint32_t bitLen = 0;
        bs.ReadCompressed(bitLen);
        printf("[RPC] id=%d (%s)  data_bits=%u\n", rpcId, rpc_id_name(rpcId), bitLen);
        break;
    }
    case ID_ONFOOT_SYNC: {
        OnFootSync s{};
        parse_onfoot_sync(bs, s);
        break;
    }
    case ID_DRIVER_SYNC: {
        DriverSync s{};
        parse_driver_sync(bs, s);
        break;
    }
    case ID_AIM_SYNC: {
        AimSync s{};
        parse_aim_sync(bs, s);
        break;
    }
    case ID_BULLET_SYNC: {
        BulletSync s{};
        parse_bullet_sync(bs, s);
        break;
    }
    case ID_WEAPONS_UPDATE: {
        WeaponsUpdate s{};
        parse_weapons_update(bs, s);
        break;
    }
    case ID_STATS_UPDATE: {
        StatsUpdate s{};
        parse_stats_update(bs, s);
        break;
    }
    case ID_UNOCCUPIED_SYNC: {
        UnoccupiedSync s{};
        parse_unoccupied_sync(bs, s);
        break;
    }
    case ID_TRAILER_SYNC: {
        TrailerSync s{};
        parse_trailer_sync(bs, s);
        break;
    }
    case ID_PASSENGER_SYNC: {
        PassengerSync s{};
        parse_passenger_sync(bs, s);
        break;
    }
    case ID_SPECTATOR_SYNC: {
        SpectatorSync s{};
        parse_spectator_sync(bs, s);
        break;
    }
    case ID_RCON_COMMAND: {
        RconCommand s{};
        parse_rcon_command(bs, s);
        break;
    }
    default:
        break;
    }
}

void samp_parse_packet(const uint8_t* buf, int len, Direction dir, uint16_t port) {
    if (len < 1) return;

    const char* dir_str = (dir == Direction::ClientToServer) ? "C->S" : "S->C";

    if (buf[0] > 0xE0) {
        printf("[%s] port=%u  RAW/OOB  len=%d  id=0x%02X\n", dir_str, port, len, buf[0]);
        return;
    }

    RakNet::BitStream bs(const_cast<uint8_t*>(buf), len, false);

    if (buf[0] == static_cast<uint8_t>(ID_OPEN_CONNECTION_REQUEST) || buf[0] == static_cast<uint8_t>(ID_OPEN_CONNECTION_REPLY) || buf[0] == static_cast<uint8_t>(ID_OPEN_CONNECTION_COOKIE))
    {
        uint8_t pkt = 0;
        bs.Read(pkt);
        printf("[%s] port=%u  PRE  pkt=%d (%s)\n", dir_str, port, pkt, packet_id_name(pkt));
        return;
    }

    bool hasAcks = false;
    bs.ReadBits(reinterpret_cast<uint8_t*>(&hasAcks), 1);

    if (hasAcks) {
        DataStructures::RangeList<uint16_t> acks;
        acks.Deserialize(&bs);
        printf("[%s] port=%u  ACK block (skipped)\n", dir_str, port);
    }

    int frameCount = 0;
    while (bs.GetNumberOfUnreadBits() > 8) {
        uint16_t seqId = 0;
        bs.Read(seqId);

        uint8_t reliability = 0;
        bs.ReadBits(&reliability, 4, true);

        uint8_t orderingChannel = 0;
        uint16_t orderingIndex = 0;
        if (reliability == UNRELIABLE_SEQUENCED || reliability == RELIABLE_SEQUENCED || reliability == RELIABLE_ORDERED)
        {
            bs.ReadBits(&orderingChannel, 5, true);
            bs.Read(orderingIndex);
        }

        bool     isSplit = false;
        uint16_t splitId = 0;
        uint32_t splitIdx = 0;
        uint32_t splitCnt = 0;
        bs.ReadBits(reinterpret_cast<uint8_t*>(&isSplit), 1);
        if (isSplit) {
            bs.Read(splitId);
            bs.ReadCompressed(splitIdx);
            bs.ReadCompressed(splitCnt);
        }

        uint16_t dataLenBits = 0;
        bs.ReadCompressed(dataLenBits);

        const int dataBytes = (dataLenBits + 7) >> 3;
        if (dataLenBits == 0 || dataBytes > 4096) {
            printf("[%s] port=%u  bad frame len=%d, stopping\n", dir_str, port, dataLenBits);
            break;
        }

        uint8_t frameData[4096] = {};
        bs.ReadAlignedBytes(frameData, dataBytes);

        if (isSplit) {
            printf("[%s] port=%u  SPLIT seqid=%-5u  part %u/%u  id=%u  rel=%s\n", dir_str, port, seqId, splitIdx + 1, splitCnt, splitId, reliability_name(reliability));
        }

        if (!isSplit || splitIdx == 0) {
            RakNet::BitStream frameBs(frameData, dataBytes, false);
            uint8_t packetId = 0;
            frameBs.Read(packetId);
            dispatch_packet(packetId, frameBs, dir, seqId);
        }

        frameCount++;
    }

    if (frameCount == 0 && !hasAcks) {
        printf("[%s] port=%u  empty datagram\n", dir_str, port);
    }
}