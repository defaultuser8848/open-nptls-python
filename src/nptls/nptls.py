import dataclasses
import enum
import json
import secrets
import time
from typing import Dict, Callable, Any, Coroutine
import asyncio
import binascii
import hashlib

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
    peer_recv_seq: int = 0  # 期望接收的下一个序列号
    connected_confirmed: bool = False

class MessageType(enum.Enum):
    MESSAGE = 0
    CONNECT = 1
    DISCONNECT = 2
    PING = 3
    PONG = 4

MAX_SEQ = (1 << 32) - 1  # 32位序列号最大值

class npTLSServer:
    def __init__(self, notepaper: Notepaper, index_page: str, name: str = "npTLS", heartbeat_interval: int = 30):
        self.name = name
        self.cli = notepaper
        self.priv_key, self.pub_key = generate_key_pair()
        self.conn_pool: Dict[str, ConnectInfo] = {}
        self.index_page = index_page
        self.msg_page = hashlib.sha256(f"nptls-msg:{self.name}-{self.index_page}".encode()).hexdigest()[:16]
        self.callbacks = []
        self.heartbeat_int = heartbeat_interval

    def add_handler(self, handler: Callable[[ConnectInfo, bytes], Coroutine]) -> None:
        self.callbacks.append(handler)
        
    def is_connected(self, conn: ConnectInfo) -> bool:
        if conn.session_id not in self.conn_pool:
            return False
        return self.conn_pool[conn.session_id].connected_confirmed
        
    def disconnect(self, conn: ConnectInfo) -> None:
        if conn.session_id in self.conn_pool:
            asyncio.create_task(self.send_message(MessageType.DISCONNECT, b"Disconnect", conn))
            del self.conn_pool[conn.session_id]
            
    async def send_message(self, type_: MessageType, data: bytes, conn: ConnectInfo) -> None:
        if not self.is_connected(conn) and type_ != MessageType.CONNECT:
            raise RuntimeError("Not connected")
            
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
        conn.send_seq = (conn.send_seq + 1) & MAX_SEQ  # 处理序列号回绕

    async def _handle_connect_request(self, sid, pkey_data: bytes) -> None:
        """处理初始的CONNECT请求（未加密）"""
        if sid in self.conn_pool:
            return
            
        try:
            peer_key = ECC.import_key(pkey_data.decode())
            ecdh = ECDH(self.priv_key, peer_key)
            self.conn_pool[sid] = ConnectInfo(
                session_id=sid,
                public_key=peer_key,
                ecdh=ecdh,
                last_active=time.time(),
                send_seq=0,
                peer_recv_seq=1 
            )
            await self.send_message(MessageType.CONNECT, b"Connected", self.conn_pool[sid])
            self.conn_pool[sid].connected_confirmed = True
        except (ValueError, binascii.Error):
            # 无效的公钥格式
            pass

    async def _handle_msg(self, data: Dict[str, Any]) -> None:
        try:
            try:
                msg_type, seq, sid, nonce, encrypted, tag = unpack_message(data["text"])
            except (binascii.Error, ValueError, KeyError, TypeError):
                return
                
            # 处理新连接的初始CONNECT请求（未加密）
            if sid not in self.conn_pool and msg_type == MessageType.CONNECT.value:
                # 这是初始连接请求，数据是未加密的公钥
                await self._handle_connect_request(sid, encrypted)
                return
                
            # 已建立的连接，进行通用序列号验证
            if sid not in self.conn_pool:
                return
                    
            conn = self.conn_pool[sid]
            
            # 验证序列号是否为期望的下一个序列号
            if seq != conn.peer_recv_seq:
                # print(f"{sid}: expected {conn.peer_recv_seq}, got {seq}")
                return
                
            # 序列号验证通过，递增期望接收的序列号
            conn.peer_recv_seq = (conn.peer_recv_seq + 1) & MAX_SEQ
            
            # 解密消息
            decrypted = conn.ecdh.decrypt(nonce, encrypted, tag)
            conn.last_active = time.time()
            
            # 处理各种消息类型
            if msg_type == MessageType.CONNECT.value:
                # 已加密的连接确认消息
                if decrypted == b"Connected":
                    conn.connected_confirmed = True
            elif msg_type == MessageType.DISCONNECT.value:
                if decrypted == b"Disconnect":
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected", conn)
                    del self.conn_pool[sid]
                elif decrypted == b"Disconnected":
                    del self.conn_pool[sid]
            elif msg_type == MessageType.PING.value:
                await self.send_message(MessageType.PONG, b"Pong", conn)
            elif msg_type == MessageType.PONG.value:
                pass  # 心跳响应，无需处理
            elif msg_type == MessageType.MESSAGE.value:
                for cb in self.callbacks:
                    asyncio.create_task(cb(conn, decrypted))
            else:
                pass  # 未知消息类型
                
        except Exception:
            pass

    async def _check_heartbeat(self):
        while True:
            to_remove = []
            for sid, conn in self.conn_pool.copy().items():
                if not self.is_connected(conn):
                    continue
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
    def __init__(self, notepaper: Notepaper, index_page: str, heartbeat_interval: int = 30):
        self.cli = notepaper
        self.priv_key, self.pub_key = generate_key_pair()
        self.ecdh = None
        self.sid = None
        self.msg_page = None
        self.server_key = None
        self.send_seq = 0  # 初始发送序列号为0
        self.peer_recv_seq = 0  # 期望接收的下一个序列号
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
            
        seq = self.send_seq
        nonce, encrypted, tag = self.ecdh.encrypt(data)
        msg = pack_message(
            msg_type=type_.value,
            nonce=nonce,
            data=encrypted,
            tag=tag,
            sid=self.sid,
            seq=seq
        )
        await self.cli.broadcast(self.msg_page, msg)
        self.send_seq = (self.send_seq + 1) & MAX_SEQ  # 处理序列号回绕
        
    async def _handle_msg(self, data):
        try:
            msg_type, seq, sid, nonce, encrypted, tag = unpack_message(data["text"])
            if sid != self.sid:
                return
                
            # 验证序列号是否为期望的下一个序列号
            if seq != self.peer_recv_seq:
                # print(f"server: expected {self.peer_recv_seq}, got {seq}")
                return
                
            # 序列号验证通过，递增期望接收的序列号
            self.peer_recv_seq = (self.peer_recv_seq + 1) & MAX_SEQ
            
            # 解密消息
            decrypted = self.ecdh.decrypt(nonce, encrypted, tag)
            self.last_active = time.time()
            
            # 处理各种消息类型
            if msg_type == MessageType.CONNECT.value:
                if decrypted == b"Connected":
                    self.conn_event.set()
            elif msg_type == MessageType.DISCONNECT.value:
                if decrypted == b"Disconnect":
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected")
                await self._cleanup()
            elif msg_type == MessageType.PING.value:
                await self.send_message(MessageType.PONG, b"Pong")
            elif msg_type == MessageType.PONG.value:
                pass  # 心跳响应，无需处理
            elif msg_type == MessageType.MESSAGE.value:
                for cb in self.callbacks:
                    asyncio.create_task(cb(decrypted))
            else:
                pass  # 未知消息类型
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
        
        # 手动打包初始CONNECT消息（未加密）
        msg = pack_message(
            msg_type=MessageType.CONNECT.value,
            nonce=bytes(16),  # 空nonce
            data=self.pub_key.export_key(format="PEM").encode(),  # 未加密的公钥
            tag=bytes(16),  # 空tag
            sid=self.sid,
            seq=0  # 初始序列号为0
        )
        await self.cli.broadcast(self.msg_page, msg)
        self.send_seq = 1  # 发送后递增序列号
        
        await self.cli.listen(self.msg_page, self._handle_msg)
        self.heartbeat_task = asyncio.create_task(self._run_heartbeat())
        await self.cli.run()