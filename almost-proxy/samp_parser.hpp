#pragma once
#include <cstdint>
#include "samp_types.hpp"
#include "raknet/BitStream.h"

enum class Direction { ClientToServer, ServerToClient };

void samp_parse_packet(const uint8_t* buf, int len, Direction dir, uint16_t port);

bool parse_onfoot_sync(RakNet::BitStream& bs, OnFootSync& out);
bool parse_driver_sync(RakNet::BitStream& bs, DriverSync& out);
bool parse_aim_sync(RakNet::BitStream& bs, AimSync& out);
bool parse_bullet_sync(RakNet::BitStream& bs, BulletSync& out);
bool parse_weapons_update(RakNet::BitStream& bs, WeaponsUpdate& out);
bool parse_stats_update(RakNet::BitStream& bs, StatsUpdate& out);
bool parse_unoccupied_sync(RakNet::BitStream& bs, UnoccupiedSync& out);
bool parse_trailer_sync(RakNet::BitStream& bs, TrailerSync& out);
bool parse_passenger_sync(RakNet::BitStream& bs, PassengerSync& out);
bool parse_spectator_sync(RakNet::BitStream& bs, SpectatorSync& out);
bool parse_rcon_command(RakNet::BitStream& bs, RconCommand& out);

const char* packet_id_name(uint8_t id);
const char* rpc_id_name(uint8_t id);
const char* reliability_name(uint8_t rel);