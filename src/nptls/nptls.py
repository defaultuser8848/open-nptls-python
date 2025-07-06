import dataclasses
import enum
import json
import secrets
import time
from typing import Dict, Callable, Any, Coroutine
import asyncio
import binascii

from .utils.ecdh import ECDH, ECC, generate_key_pair
from .utils.notepaper import Notepaper
from .utils.pack import pack_message, unpack_message

@dataclasses.dataclass
class ConnectInfo:
    session_id: str
    public_key: ECC.EccKey
    ecdh: ECDH
    last_active: float
    send_seq: int = 0
    peer_recv_seq: int = 0
    connected_confirmed: bool = False

class MessageType(enum.Enum):
    MESSAGE = 0
    CONNECT = 1
    DISCONNECT = 2
    PING = 3
    PONG = 4

class npTLSServer:
    def __init__(self, notepaper: Notepaper, index_page: str, name: str = "npTLS", heartbeat_interval: int = 5):
        self.name = name
        self.cli = notepaper
        self.priv_key, self.pub_key = generate_key_pair()
        self.conn_pool: Dict[str, ConnectInfo] = {}
        self.index_page = index_page
        self.msg_page = secrets.token_urlsafe(16)
        self.callbacks = []
        self.heartbeat_int = heartbeat_interval

    def add_handler(self, handler: Callable[[ConnectInfo, bytes], Coroutine]) -> None:
        self.callbacks.append(handler)

    async def send_message(self, type_: MessageType, data: bytes, conn: ConnectInfo) -> None:
        seq = conn.send_seq
        nonce, encrypted, tag = conn.ecdh.encrypt(data)
        msg = pack_message(
            msg_type=type_.value,
            nonce=nonce,
            data=encrypted,
            tag=tag,
            sid=conn.session_id,
            seq=seq
        )
        await self.cli.broadcast(self.msg_page, msg)
        conn.send_seq += 1

    async def _handle_connect(self, sid, pkey) -> None:
        if sid in self.conn_pool:
            return
            
        peer_key = ECC.import_key(pkey)
        ecdh = ECDH(self.priv_key, peer_key)
        self.conn_pool[sid] = ConnectInfo(
            session_id=sid,
            public_key=peer_key,
            ecdh=ecdh,
            last_active=time.time()
        )
        await self.send_message(MessageType.CONNECT, b"Connected", self.conn_pool[sid])
        self.conn_pool[sid].connected_confirmed = True

    async def _handle_msg(self, data: Dict[str, Any]) -> None:
        try:
            try:
                msg_type, seq, sid, nonce, encrypted, tag = unpack_message(data["text"])
            except (binascii.Error, ValueError, KeyError, TypeError):
                return
                
            if sid not in self.conn_pool:
                if msg_type == MessageType.CONNECT.value:
                    await self._handle_connect(sid=sid, pkey=encrypted)
                return
                
            conn = self.conn_pool[sid]
            
            if msg_type == MessageType.CONNECT.value:
                if seq != 0:
                    return
                conn.connected_confirmed = True
                conn.last_active = time.time()
                return
                
            if seq != conn.peer_recv_seq + 1:
                return
                
            decrypted = conn.ecdh.decrypt(nonce, encrypted, tag)
            conn.peer_recv_seq = seq
            conn.last_active = time.time()
            
            if msg_type == MessageType.DISCONNECT.value:
                if decrypted == b"Disconnect":
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected", conn)
                    del self.conn_pool[sid]
                elif decrypted == b"Disconnected":
                    del self.conn_pool[sid]
                return
            elif msg_type == MessageType.PING.value:
                await self.send_message(MessageType.PONG, b"Pong", conn)
                return
            elif msg_type == MessageType.PONG.value:
                return
            elif msg_type == MessageType.MESSAGE.value:
                for cb in self.callbacks:
                    asyncio.create_task(cb(conn, decrypted))
            else:
                pass
        except Exception:
            pass

    async def _check_heartbeat(self):
        while True:
            to_remove = []
            for sid, conn in self.conn_pool.copy().items():
                if time.time() - conn.last_active > self.heartbeat_int:
                    await self.send_message(MessageType.PING, b"Ping", conn)
                if time.time() - conn.last_active > self.heartbeat_int * 2:
                    to_remove.append(sid)
                    
            for sid in to_remove:
                if sid in self.conn_pool:
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected", self.conn_pool[sid])
                    del self.conn_pool[sid]
                    
            await asyncio.sleep(self.heartbeat_int)

    async def run(self):
        await self.cli.listen(self.msg_page, self._handle_msg)
        await self.cli.broadcast(self.index_page, json.dumps({
            "name": self.name,
            "public_key": self.pub_key.export_key(format='PEM'),
            "message_page": self.msg_page,
            "version": "0.1.0",
        }, indent=4))
        await asyncio.gather(self.cli.run(), self._check_heartbeat())

class npTLSClient:
    def __init__(self, notepaper: Notepaper, index_page: str, heartbeat_interval: int = 5):
        self.cli = notepaper
        self.priv_key, self.pub_key = generate_key_pair()
        self.ecdh = None
        self.sid = None
        self.msg_page = None
        self.server_key = None
        self.send_seq = 0
        self.peer_recv_seq = 0
        self.index_page = index_page
        self.conn_event = asyncio.Event()
        self.callbacks = []
        self.heartbeat_int = heartbeat_interval
        self.last_active = time.time()
        self.heartbeat_task = None

    def add_handler(self, handler: Callable[[bytes], Coroutine]):
        self.callbacks.append(handler)

    async def send_message(self, type_: MessageType, data: bytes):
        if not self.conn_event.is_set() and type_ != MessageType.CONNECT:
            raise RuntimeError("Not connected")
        if not all([self.ecdh, self.sid, self.msg_page]):
            raise RuntimeError("Handshake incomplete")
            
        self.send_seq += 1
        nonce, encrypted, tag = self.ecdh.encrypt(data)
        msg = pack_message(
            msg_type=type_.value,
            nonce=nonce,
            data=encrypted,
            tag=tag,
            sid=self.sid,
            seq=self.send_seq
        )
        await self.cli.broadcast(self.msg_page, msg)

    async def _handle_msg(self, data):
        try:
            msg_type, seq, sid, nonce, encrypted, tag = unpack_message(data["text"])
            if sid != self.sid:
                return
                
            if msg_type == MessageType.CONNECT.value:
                if seq != 0:
                    return
                decrypted = self.ecdh.decrypt(nonce, encrypted, tag)
                self.last_active = time.time()
                if decrypted == b"Connected":
                    self.conn_event.set()
                return
                
            if seq != self.peer_recv_seq + 1:
                return
                
            decrypted = self.ecdh.decrypt(nonce, encrypted, tag)
            self.peer_recv_seq = seq
            self.last_active = time.time()
            
            if msg_type == MessageType.DISCONNECT.value:
                if decrypted == b"Disconnect":
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected")
                await self._cleanup()
                return
            elif msg_type == MessageType.PING.value:
                await self.send_message(MessageType.PONG, b"Pong")
                return
            elif msg_type == MessageType.PONG.value:
                return
            elif msg_type == MessageType.MESSAGE.value:
                for cb in self.callbacks:
                    asyncio.create_task(cb(decrypted))
            else:
                pass
        except Exception:
            pass

    async def _run_heartbeat(self):
        while self.conn_event.is_set():
            if time.time() - self.last_active > self.heartbeat_int:
                await self.send_message(MessageType.PING, b"Ping")
            if time.time() - self.last_active > self.heartbeat_int * 2:
                await self.send_message(MessageType.DISCONNECT, b"Disconnected")
                await self._cleanup()
                break
            await asyncio.sleep(self.heartbeat_int)

    async def disconnect(self):
        if not self.conn_event.is_set():
            return
            
        try:
            await self.send_message(MessageType.DISCONNECT, b"Disconnect")
        except Exception:
            pass
        finally:
            await self._cleanup()

    async def _cleanup(self):
        self.conn_event.clear()
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        await self.cli.close()

    async def run(self):
        self.conn_event.clear()
        index_data = json.loads(await self.cli.get_content(self.index_page))
        self.server_key = ECC.import_key(index_data["public_key"])
        self.msg_page = index_data["message_page"]
        self.ecdh = ECDH(self.priv_key, self.server_key)
        self.sid = secrets.token_urlsafe(6)
        
        await self.cli.broadcast(self.msg_page, pack_message(
            msg_type=MessageType.CONNECT.value,
            nonce=bytes(16),
            data=self.pub_key.export_key(format="PEM").encode(),
            tag=bytes(16),
            sid=self.sid,
            seq=0))
            
        await self.cli.listen(self.msg_page, self._handle_msg)
        self.heartbeat_task = asyncio.create_task(self._run_heartbeat())
        await self.cli.run()