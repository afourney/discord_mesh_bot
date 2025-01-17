#!/usr/bin/env python3
import string
import sqlite3
import time
import warnings

import base64
import os
import requests
import yaml
import threading

import paho.mqtt.client as paho
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from meshtastic import BROADCAST_NUM
from meshtastic.protobuf import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2

DEFAULT_KEY = "1PG7OiApB1nwvP+rz05pAQ=="  # AQ==, expanded

CONFIG = {}

hist = {}
conn = None
lock = threading.Lock()


def sender_id(mp: mesh_pb2.MeshPacket):
    """
    Given a MeshPacket, return the "sender id" which is a hex
    representation of the last 8 bytes of the MAC address.

    For example, !ff11ff22
    """
    return "!" + "{0:#0{1}x}".format(getattr(mp, "from"), 8)[2:]


def discord_message_key(se: mqtt_pb2.ServiceEnvelope, mp: mesh_pb2.MeshPacket):
    """
    Rudimentary key to deduplicate messages.
    TODO: See what Meshtastic does here to deduplicate packets, maybe we can do the same?
    """
    return f"{se.channel_id}::{sender_id(mp)}::{mp.decoded.payload.decode('utf-8')}"


class DiscordMessage:
    """
    Object representing the information we want to expose via Discord messages.

    We store this object in memory so we can update messages as more nodes
    report hearing them.
    """

    mesh_packets = []
    discord_message_id = None

    def __init__(self, channel_id: str, gateway_id: str, mp: mesh_pb2.MeshPacket):
        """
        Construct discord message from Meshtastic protobuf.
        """
        self.from_id = sender_id(mp)
        self.channel_id = channel_id
        self.message_text = mp.decoded.payload.decode("utf-8")

        self.add_meshpacket(gateway_id, mp)

    def add_meshpacket(self, gateway_id: str, mp: mesh_pb2.MeshPacket):
        self.mesh_packets.append((gateway_id, mp))

    def render(self):
        """
        Renders the message out as a Discord-compatible dictionary.
        """

        primary_embed = {
            "description": "```" + self.message_text.replace("`", "'") + " ```",
            "author": {
                "name": node_long_name(conn, self.from_id),
            },
            "footer": {
                "text": f"{self.channel_id}",
            },
        }

        stats_desc = ""
        index = 1
        for gateway_id, mp in self.mesh_packets:
            if gateway_id == self.from_id:
                stats_desc += f"{index}. self-gated\n"
            else:
                stats_desc += (
                    f"{index}. {node_long_name(conn, gateway_id)} (SNR: {mp.rx_snr})\n"
                )

        stats_embed = {
            "author": {"name": "Statistics"},
            "description": stats_desc,
        }

        discord_data = {"embeds": [primary_embed, stats_embed]}

        return discord_data

    def publish(self, config) -> str:
        """
        Posts the message to Discord channel with the provided config.
        """
        query_params = {
            "thread_id": config.get("thread", None),
            "wait": True,
        }

        url = config["webhook"]

        if self.discord_message_id:
            url += f"/messages/{self.discord_message_id}"
            response = requests.patch(url, params=query_params, json=self.render())
        else:
            response = requests.post(url, params=query_params, json=self.render())

        if response.status_code == 200:
            self.discord_message_id = response.json()["id"]
        else:
            print(f"Failed to send message. Status code: {response.status_code}")
            print(response.text)


def on_message(mosq, obj, msg):
    with lock:
        se = mqtt_pb2.ServiceEnvelope()
        try:
            se.ParseFromString(msg.payload)
            mp = se.packet
        except Exception as e:
            print(f"*** ServiceEnvelope: {str(e)}")
            return

        # What do we know about this channel?
        channel_config = CONFIG["channels"].get(se.channel_id, CONFIG["catch_all"])

        # Decrypt the message if possible
        if mp.HasField("encrypted") and not mp.HasField("decoded"):
            decode_encrypted(mp, channel_config.get("key", DEFAULT_KEY))

        # print("")
        # print("Service Envelope:")
        # print("=" * 80)
        # print(se)

        if not mp.HasField("decoded"):
            # Decoding failed.
            return

        if mp.decoded.portnum == portnums_pb2.TEXT_MESSAGE_APP:
            try:
                if mp.to != BROADCAST_NUM:  # Broadcast
                    return

                if "webhook" not in channel_config:
                    # Nowhere to post
                    warnings.warn(
                        "No webhook configured for channel '" + se.channel_id + "'"
                    )
                    return

                history_key = discord_message_key(se, mp)
                if history_key not in hist:
                    print(f"New message: {history_key}")
                    discord_msg = DiscordMessage(se.channel_id, se.gateway_id, mp)
                    hist[history_key] = discord_msg
                else:
                    # We've seen this message before, update the stored
                    # message with the latest ServiceEnvelope and MeshPacket
                    print(f"Existing message: {history_key}")
                    discord_msg = hist[history_key]
                    discord_msg.add_meshpacket(se.gateway_id, mp)

                discord_msg.publish(channel_config)
            except Exception as e:
                print(f"*** TEXT_MESSAGE_APP: {str(e)}")

        elif mp.decoded.portnum == portnums_pb2.NODEINFO_APP:
            info = mesh_pb2.User()
            try:
                info.ParseFromString(mp.decoded.payload)
                # print(f"id: {info.id}")
                # print(f"long_name: {info.long_name}")
                # print(f"short_name: {info.short_name}")
                # print(f"hw_model: {info.hw_model}")
                # print(f"pubkey: {base64.b64encode(info.public_key)}")
                insert_db(
                    conn,
                    info.id,
                    info.long_name,
                    info.short_name,
                    info.hw_model,
                    base64.b64encode(info.public_key),
                )

            except Exception as e:
                print(f"*** NODEINFO_APP: {str(e)}")

        elif mp.decoded.portnum == portnums_pb2.POSITION_APP:
            pos = mesh_pb2.Position()
            try:
                pos.ParseFromString(mp.decoded.payload)
                # print(pos)
            except Exception as e:
                print(f"*** POSITION_APP: {str(e)}")

        elif mp.decoded.portnum == portnums_pb2.TELEMETRY_APP:
            env = telemetry_pb2.Telemetry()
            try:
                env.ParseFromString(mp.decoded.payload)
                # print(env)
            except Exception as e:
                print(f"*** TELEMETRY_APP: {str(e)}")


def on_publish(mosq, obj, mid, reason_codes, properties):
    print("Publish")


def on_connect(client, userdata, flags, reason_code, properties):
    print(f"Connected with result code {reason_code}")


def decode_encrypted(mp, key):
    """Decrypt a meshtastic message."""

    try:
        # Expand the default key
        if key == "AQ==":
            key = DEFAULT_KEY

        # Convert key to bytes
        key_bytes = base64.b64decode(key.encode("ascii"))

        nonce_packet_id = getattr(mp, "id").to_bytes(8, "little")
        nonce_from_node = getattr(mp, "from").to_bytes(8, "little")

        # Put both parts into a single byte array.
        nonce = nonce_packet_id + nonce_from_node

        cipher = Cipher(
            algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_bytes = (
            decryptor.update(getattr(mp, "encrypted")) + decryptor.finalize()
        )

        data = mesh_pb2.Data()
        data.ParseFromString(decrypted_bytes)
        mp.decoded.CopyFrom(data)

    except Exception as e:
        print(f"*** Decryption failed: {str(e)}")


def create_db(conn):
    cursor = conn.cursor()
    cursor.execute(
        """
CREATE TABLE IF NOT EXISTS Nodes (
    id TEXT NOT NULL PRIMARY KEY,
    timestamp INTEGER,
    long_name TEXT,
    short_name TEXT,
    hw_model INTEGER,
    public_key TEXT
);
"""
    )
    conn.commit()
    cursor.close()


def insert_db(conn, nodeid, long_name, short_name, hw_model, public_key):
    cursor = conn.cursor()
    cursor.execute(
        """
INSERT OR REPLACE INTO Nodes 
    (id, timestamp, long_name, short_name, hw_model, public_key)
VALUES (?, ?, ?, ?, ?, ?);
""",
        (nodeid, time.time(), long_name, short_name, hw_model, public_key),
    )
    conn.commit()
    cursor.close()


def node_lookup(conn, nodeid):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, timestamp, long_name, short_name, hw_model, public_key FROM Nodes WHERE id = ?",
        (nodeid,),
    )
    row = cursor.fetchone()
    result = None
    if row:
        result = {
            "id": row[0],
            "timestamp": row[1],
            "long_name": row[2],
            "short_name": row[3],
            "hw_model": row[4],
            "public_key": row[5],
        }
    cursor.close()
    return result


def node_long_name(conn, nodeid):
    db_res = node_lookup(conn, nodeid)
    if db_res:
        return db_res["long_name"]
    else:
        return nodeid


if __name__ == "__main__":
    # Load the YAML config file, replacing environment variables
    def string_constructor(loader, node):
        t = string.Template(node.value)
        value = t.safe_substitute(os.environ)
        return value

    l = yaml.SafeLoader
    l.add_constructor("tag:yaml.org,2002:str", string_constructor)

    token_re = string.Template.pattern
    l.add_implicit_resolver("tag:yaml.org,2002:str", token_re, None)

    with open("config.yaml", "r") as file:
        CONFIG = yaml.load(file, Loader=l)

    # Fold the channel list into a dictionary
    d = {}
    for c in CONFIG["channels"]:
        d[c["name"]] = c
    CONFIG["channels"] = d

    # Read the nodes database
    conn = sqlite3.connect("nodes.db")
    create_db(conn)

    # Start the MQTT client
    client = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id="ctso-bot-dev")
    client.on_message = on_message
    client.on_publish = on_publish
    client.on_connect = on_connect

    client.username_pw_set(CONFIG["mqtt"]["user"], CONFIG["mqtt"]["password"])
    client.connect(CONFIG["mqtt"]["address"], CONFIG["mqtt"]["port"], 60)
    client.subscribe(CONFIG["mqtt"]["subscription"], 0)

    while client.loop() == 0:
        pass

    conn.close()
