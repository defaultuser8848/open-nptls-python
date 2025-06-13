import base64
import dataclasses
import enum
import json
import secrets
import time
from typing import Dict, Callable, Any,Coroutine
import asyncio
import binascii

import msgpack

from utils.ecdh import ECDH, ECC,generate_key_pair
from utils.notepaper import Notepaper

@dataclasses.dataclass
class ConnectInfo:
    session_id: str
    public_key: ECC.EccKey
    ecdh: ECDH
    last_active: float
    send_seq: int = 1 
    peer_recv_seq: int = 0 
    connected_confirmed: bool = False  # 新增：标记握手是否完成


class MessageType(enum.Enum):
    MESSAGE = 0
    CONNECT = 1
    DISCONNECT = 2
    PING = 3
    PONG = 4
class npTLSServer():
    def __init__(self,notepaper: Notepaper, index_page:str,name:str="npTLS",heartbeat_interval: int = 5):
        self.name = name
        self.cli = notepaper
        self.priv_key,self.pub_key = generate_key_pair()
        self.connect_pool: Dict[str, ConnectInfo] = {}
        self.index_page = index_page
        self.message_page = secrets.token_urlsafe(16)
        self.connect_page = secrets.token_urlsafe(16)
        self.callbacks: list[Callable[[ConnectInfo,bytes], Coroutine]] = []
        self.heartbeat_interval = heartbeat_interval
    def add_handler(self,handler: Callable[[ConnectInfo,bytes], Coroutine]) -> None:
        self.callbacks.append(handler)
    async def send_message(self, type_: MessageType, data: bytes, conn_info: ConnectInfo) -> None:

        if type_ == MessageType.CONNECT:
            seq = 0
        else:
            seq = conn_info.send_seq
            conn_info.send_seq += 1
        nonce, encrypted, tag = conn_info.ecdh.encrypt(data)
        msg: str = base64.b85encode(msgpack.packb({
            "type": type_.value,
            "nonce": nonce,
            "data": encrypted,
            "tag": tag,
            "sid": conn_info.session_id,
            "seq": seq,
        })).decode()
        await self.cli.broadcast(self.message_page, msg)
    async def _connect_handler(self, data: Dict[str, Any]) -> None:
        try:
            try:
                msg_data = msgpack.unpackb(base64.b85decode(data["text"]))
            except (binascii.Error, msgpack.exceptions.UnpackException, KeyError, TypeError, ValueError):
                return
            if "sid" not in msg_data or "pkey" not in msg_data:
                return
            session_id = msg_data["sid"]
            print(session_id)
            if session_id in self.connect_pool:
                # 已有连接，忽略重复连接请求
                return
            peer_public_key = ECC.import_key(msg_data["pkey"])
            ecdh = ECDH(self.priv_key, peer_public_key)
            self.connect_pool[session_id] = ConnectInfo(
                session_id=session_id,
                public_key=peer_public_key,
                ecdh=ecdh,
                last_active=time.time()
            )
            self.connect_pool[session_id].connected_confirmed = False
            # 收到 Connect 指令，回复 Connected 确认
            await self.send_message(MessageType.CONNECT, b"Connected", self.connect_pool[session_id])
            self.connect_pool[session_id].connected_confirmed = True
        except Exception as e:
            print(f"连接处理异常: {e}")
            return
    async def _message_handler(self, data: Dict[str, Any]) -> None:
        try:
            try:
                msg_data = msgpack.unpackb(base64.b85decode(data["text"]))
            except (binascii.Error, msgpack.exceptions.UnpackException, KeyError, TypeError, ValueError):
                return
            if "sid" not in msg_data or "seq" not in msg_data:
                return
            session_id = msg_data["sid"]
            seq = msg_data["seq"]
            if session_id not in self.connect_pool:
                return
            conn_info = self.connect_pool[session_id]
            if seq != 0 and seq != conn_info.peer_recv_seq + 1:
                print(f"[丢弃] 服务端乱序包 seq={seq}, 期望={conn_info.peer_recv_seq+1}")
                return
            decrypted = conn_info.ecdh.decrypt(msg_data["nonce"], msg_data["data"], msg_data["tag"])
            if seq != 0:
                conn_info.peer_recv_seq = seq
            conn_info.last_active = time.time()
            if msg_data["type"] == MessageType.CONNECT.value:
                conn_info.connected_confirmed = True
                return
            # 明确区分 Disconnect（请求）和 Disconnected（确认）
            if msg_data["type"] == MessageType.DISCONNECT.value:
                if decrypted == b"Disconnect":
                    # 收到断开请求，回复 Disconnected 并移除连接
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected", conn_info)
                    del self.connect_pool[session_id]
                elif decrypted == b"Disconnected":
                    # 收到断开确认，移除连接
                    del self.connect_pool[session_id]
                return
            if msg_data["type"] == MessageType.PING.value:
                await self.send_message(MessageType.PONG, b"Pong", conn_info)
                return
            if msg_data["type"] == MessageType.PONG.value:
                return
            if msg_data["type"] != MessageType.MESSAGE.value:
                print(f"未知消息类型: {msg_data['type']}")
                return
            for callback in self.callbacks:
                asyncio.create_task(callback(
                    self.connect_pool[session_id],
                    decrypted
                ))
        except ValueError as e:
            print(f"消息解密失败: {e}")
        except Exception as e:
            print(f"消息处理异常: {e}")
    async def heartbeat_check(self):
        while True:
            to_remove = []
            for (sid,conn) in self.connect_pool.copy().items():
                if time.time()-conn.last_active > self.heartbeat_interval:
                    await self.send_message(MessageType.PING, b"Ping", conn)
                if time.time()-conn.last_active > self.heartbeat_interval*2:
                    to_remove.append(sid)
            for sid in to_remove:
                await self.send_message(MessageType.DISCONNECT, b"Disconnected", self.connect_pool[sid])
                del self.connect_pool[sid]
            await asyncio.sleep(self.heartbeat_interval)
                    
    async def run(self):
        await self.cli.listen(self.connect_page, self._connect_handler)
        await self.cli.listen(self.message_page, self._message_handler)
        await self.cli.broadcast(self.index_page, json.dumps({
            "name": self.name,
            "public_key": self.pub_key.export_key(format='PEM'),
            "connect_page": self.connect_page,
            "message_page": self.message_page,
            "version": "0.1.0",
        },indent=4))
        await asyncio.gather(self.cli.run(),self.heartbeat_check())


class npTLSClient:
    def __init__(self, notepaper: Notepaper, index_page: str):
        self.cli: Notepaper = notepaper
        self.priv_key, self.pub_key = generate_key_pair()
        self.ecdh: ECDH | None = None
        self.session_id: str | None = None
        self.message_page: str | None = None
        self.connect_page: str | None = None
        self.server_pubkey: ECC.EccKey | None = None
        self.send_seq: int = 1
        self.peer_recv_seq: int = 0
        self.index_page: str = index_page
        self.connected_event = asyncio.Event()
        self.callbacks: list[Callable[[bytes], Coroutine]] = []
        self._handshake_confirmed = False
        self._disconnecting = False

    def add_handler(self, handler: Callable[[bytes], Coroutine]):
        self.callbacks.append(handler)

    async def _handle_message(self, data):
        try:
            msg_data = msgpack.unpackb(base64.b85decode(data["text"]))
            print(msg_data)
            if msg_data.get("sid") != self.session_id:
                return
            if "seq" not in msg_data or "type" not in msg_data or "nonce" not in msg_data or "data" not in msg_data or "tag" not in msg_data:
                return
            seq = msg_data["seq"]
            if seq != 0:
                if seq != self.peer_recv_seq + 1:
                    print(f"[丢弃] 服务端乱序包 seq={seq}, 期望={self.peer_recv_seq+1}")
                    return
            type_ = msg_data["type"]
            nonce = msg_data["nonce"]
            encrypted = msg_data["data"]
            tag = msg_data["tag"]
            decrypted = self.ecdh.decrypt(nonce, encrypted, tag)
            # 只处理服务端 Connected 确认
            if seq != 0:
                self.peer_recv_seq = seq
            if type_ == MessageType.CONNECT.value and decrypted == b"Connected":
                self._handshake_confirmed = True
                self.connected_event.set()
                return
            if type_ == MessageType.DISCONNECT.value:
                if decrypted == b"Disconnect":
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected")
                    self.connected_event.clear()
                    self._disconnecting = False
                elif decrypted == b"Disconnected":
                    self.connected_event.clear()
                    self._disconnecting = False
                return
            if type_ == MessageType.PING.value:
                await self.send_message(MessageType.PONG, b"Pong")
                return
            for cb in self.callbacks:
                asyncio.create_task(cb(decrypted))
        except Exception as e:
            print(f"[消息解密失败] {e}")

    async def send_message(self, type_: MessageType, data: bytes):
        if not self.connected_event.is_set() and type_ != MessageType.CONNECT:
            raise RuntimeError("Not connected. Call connect() first.")
        if self.ecdh is None or self.session_id is None or self.message_page is None:
            raise RuntimeError("Handshake not completed or missing required attributes.")
        if type_ == MessageType.CONNECT:
            seq = 0
        else:
            seq = self.send_seq
            self.send_seq += 1
        nonce, encrypted, tag = self.ecdh.encrypt(data)
        msg = base64.b85encode(msgpack.packb({
            "type": type_.value,
            "nonce": nonce,
            "data": encrypted,
            "tag": tag,
            "sid": self.session_id,
            "seq": seq
        })).decode()
        await self.cli.broadcast(self.message_page, msg)

    async def disconnect(self):
        if not self.connected_event.is_set() or self._disconnecting:
            return
        self._disconnecting = True
        await self.send_message(MessageType.DISCONNECT, b"Disconnect")
        # 等待对方确认
        for _ in range(30):
            if not self.connected_event.is_set():
                break
            await asyncio.sleep(0.1)
        self._disconnecting = False

    async def run(self):
        self._handshake_confirmed = False
        self.connected_event.clear()
        index_raw = await self.cli.get_content(self.index_page)
        index_data = json.loads(index_raw)
        self.server_pubkey = ECC.import_key(index_data["public_key"])
        self.connect_page = index_data["connect_page"]
        self.message_page = index_data["message_page"]
        self.ecdh = ECDH(self.priv_key, self.server_pubkey)
        self.session_id = secrets.token_urlsafe(8)
        connect_info = {
            "sid": self.session_id,
            "pkey": self.pub_key.export_key(format="PEM"),
            "seq": 0
        }
        connect_msg = base64.b85encode(msgpack.packb(connect_info)).decode()
        # 发送 Connect 指令
        await self.cli.broadcast(self.connect_page, connect_msg)
        await self.cli.listen(self.message_page, self._handle_message)
        await self.cli.run()

        
