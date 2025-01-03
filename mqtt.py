#!/usr/bin/env python3

import paho.mqtt.client as paho
import base64
import requests
import sqlite3
import time
import json
import yaml
import string
import os
import warnings

from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic.protobuf import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2
from meshtastic import BROADCAST_NUM

DEFAULT_KEY = "1PG7OiApB1nwvP+rz05pAQ==" # AQ==, expanded
BROADCAST_ADDR = 4294967295 # 'to:' address, for broadcasts

CONFIG = {}

hist = {}
conn = None

def on_message(mosq, obj, msg):
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

    print ("")
    print ("Service Envelope:")
    print ("="*80)
    print (se)

    if not mp.HasField("decoded"):
        # Decoding failed.
        return 

    if mp.decoded.portnum == portnums_pb2.TEXT_MESSAGE_APP:
        
        if mp.to != BROADCAST_ADDR: # Broadcast
            return
    
        if "webhook" not in channel_config:
            # Nowhere to post
            warnings.warn("No webhook configured for channel '" + se.channel_id + "'")
            return

        try:
            text_payload = mp.decoded.payload.decode("utf-8")
            _from = "!"+ "{0:#0{1}x}".format(getattr(mp, 'from'),8)[2:]

            _gateway = se.gateway_id
            _channel_id = se.channel_id
            _topic = msg.topic
            _is_self_gate = _from == _gateway 

            _node_info = node_lookup(conn, _from)
            _gateway_info = node_lookup(conn, _gateway)

            _key = _channel_id + "::" + _from + "::" + text_payload

            if _node_info is not None:
                _from = f"{_node_info['long_name']}"
            if _gateway_info is not None:
                _gateway = f"{_gateway_info['long_name']}"

            now = datetime.now()
            iso_now = now.isoformat()

            discord_msg = {
                "embeds": [{
                    "description": "```" + text_payload.replace("`", "'") + " ```",
                    #"timestamp": iso_now,
                    "author": {
                        "name": _from,
                    },
                    "footer": {
                        "text": f"{_channel_id}",
                    },
                 }]
            }   

            if "map_url_prefix" in CONFIG["mqtt"]:
                discord_msg["embeds"][0]["author"]["url"] = CONFIG["mqtt"]["map_url_prefix"] + str(getattr(mp, 'from'))

            if not _is_self_gate:
                discord_msg["embeds"][0]["footer"]["text"] += f" (via: {_gateway})"

            if _key not in hist:
                hist[_key] = True
                print(json.dumps(discord_msg, indent=4))

                thread_param = ""
                if "thread" in channel_config:
                    thread_param = "?thread_id=" + str(channel_config["thread"])

                post_discord(discord_msg, channel_config["webhook"] + thread_param)

        except Exception as e:
            print(f"*** TEXT_MESSAGE_APP: {str(e)}")

    elif mp.decoded.portnum == portnums_pb2.NODEINFO_APP:
        info = mesh_pb2.User()
        try:
            info.ParseFromString(mp.decoded.payload)
            print(f"id: {info.id}")
            print(f"long_name: {info.long_name}")
            print(f"short_name: {info.short_name}")
            print(f"hw_model: {info.hw_model}")
            print(f"pubkey: {base64.b64encode(info.public_key)}")
            insert_db(conn, info.id, info.long_name, info.short_name, info.hw_model, base64.b64encode(info.public_key))

        except Exception as e:
            print(f"*** NODEINFO_APP: {str(e)}")

    elif mp.decoded.portnum == portnums_pb2.POSITION_APP:
        pos = mesh_pb2.Position()
        try:
            pos.ParseFromString(mp.decoded.payload)
            print(pos)
        except Exception as e:
            print(f"*** POSITION_APP: {str(e)}")

    elif mp.decoded.portnum == portnums_pb2.TELEMETRY_APP:
        env = telemetry_pb2.Telemetry()
        try:
            env.ParseFromString(mp.decoded.payload)
            print(env)
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
        key_bytes = base64.b64decode(key.encode('ascii'))

        nonce_packet_id = getattr(mp, "id").to_bytes(8, "little")
        nonce_from_node = getattr(mp, "from").to_bytes(8, "little")

        # Put both parts into a single byte array.
        nonce = nonce_packet_id + nonce_from_node

        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(getattr(mp, "encrypted")) + decryptor.finalize()

        data = mesh_pb2.Data()
        data.ParseFromString(decrypted_bytes)
        mp.decoded.CopyFrom(data)

    except Exception as e:
        print(f"*** Decryption failed: {str(e)}")


def post_discord(msg, webhook):
    if isinstance(msg, str):
        data = {
            "content": text
        }
    else:
        data = msg

    response = requests.post(webhook, json=data)
    if response.status_code == 204:
        pass
    else:
        print(f"Failed to send message. Status code: {response.status_code}")
        print(response.text)


def create_db(conn):
    cursor = conn.cursor()
    cursor.execute("""
CREATE TABLE IF NOT EXISTS Nodes (
    id TEXT NOT NULL PRIMARY KEY,
    timestamp INTEGER,
    long_name TEXT,
    short_name TEXT,
    hw_model INTEGER,
    public_key TEXT
);
""")
    conn.commit()
    cursor.close()


def insert_db(conn, nodeid, long_name, short_name, hw_model, public_key):
    cursor = conn.cursor()
    cursor.execute("""
INSERT OR REPLACE INTO Nodes 
    (id, timestamp, long_name, short_name, hw_model, public_key)
VALUES (?, ?, ?, ?, ?, ?);
""", (nodeid, time.time(), long_name, short_name, hw_model, public_key))
    conn.commit()
    cursor.close()


def node_lookup(conn, nodeid):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, timestamp, long_name, short_name, hw_model, public_key FROM Nodes WHERE id = ?", (nodeid,)
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


if __name__ == '__main__':

    # Load the YAML config file, replacing environment variables
    def string_constructor(loader, node):
        t = string.Template(node.value)
        value = t.safe_substitute(os.environ)
        return value

    l = yaml.SafeLoader
    l.add_constructor('tag:yaml.org,2002:str', string_constructor)

    token_re = string.Template.pattern
    l.add_implicit_resolver('tag:yaml.org,2002:str', token_re, None)
 
    with open("config.yaml", "r") as file:
        CONFIG = yaml.load(file, Loader=l)

    # Fold the channel list into a dictionary
    d = dict()
    for c in CONFIG["channels"]:
       d[c["name"]] = c
    CONFIG["channels"] = d

    # Read the nodes database
    conn = sqlite3.connect("nodes.db")
    create_db(conn)

    # Start the MQTT client
    client = paho.Client(paho.CallbackAPIVersion.VERSION2, client_id="meshobserv-7362")
    client.on_message = on_message
    client.on_publish = on_publish
    client.on_connect = on_connect

    client.username_pw_set(CONFIG["mqtt"]["user"], CONFIG["mqtt"]["password"])
    client.connect(CONFIG["mqtt"]["address"], CONFIG["mqtt"]["port"], 60)
    client.subscribe(CONFIG["mqtt"]["subscription"], 0)
    
    while client.loop() == 0:
        pass

    conn.close()
