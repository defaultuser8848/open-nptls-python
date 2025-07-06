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
from .utils.pack import pack_message,unpack_message
@dataclasses.dataclass
class ConnectInfo:
    session_id: str
    public_key: ECC.EccKey
    ecdh: ECDH
    last_active: float
    send_seq: int = 0
    peer_recv_seq: int = 0
    connected_confirmed: bool = False  # 标记握手是否完成


class MessageType(enum.Enum):
    MESSAGE = 0
    CONNECT = 1
    DISCONNECT = 2
    PING = 3
    PONG = 4


class npTLSServer():
    def __init__(self, notepaper: Notepaper, index_page: str, name: str = "npTLS", heartbeat_interval: int = 5):
        self.name = name
        self.cli = notepaper
        self.priv_key, self.pub_key = generate_key_pair()
        self.connect_pool: Dict[str, ConnectInfo] = {}
        self.index_page = index_page
        self.message_page = secrets.token_urlsafe(16)
        self.callbacks: list[Callable[[ConnectInfo, bytes], Coroutine]] = []
        self.heartbeat_interval = heartbeat_interval

    def add_handler(self, handler: Callable[[ConnectInfo, bytes], Coroutine]) -> None:
        self.callbacks.append(handler)

    async def send_message(self, type_: MessageType, data: bytes, conn_info: ConnectInfo) -> None:
        seq = conn_info.send_seq
        nonce, encrypted, tag = conn_info.ecdh.encrypt(data)
        msg: str = pack_message(
            msg_type=type_.value,
            nonce=nonce,
            data=encrypted,
            tag=tag,
            sid=conn_info.session_id,
            seq=seq
        )
        await self.cli.broadcast(self.message_page, msg)
        conn_info.send_seq += 1

    async def _connect_handler(self, session_id,pkey) -> None:
        if session_id in self.connect_pool:
            return
            
        peer_public_key = ECC.import_key(pkey)
        ecdh = ECDH(self.priv_key, peer_public_key)
        self.connect_pool[session_id] = ConnectInfo(
            session_id=session_id,
            public_key=peer_public_key,
            ecdh=ecdh,
            last_active=time.time()
        )
        await self.send_message(MessageType.CONNECT, b"Connected", self.connect_pool[session_id])
        self.connect_pool[session_id].connected_confirmed = True

    async def _message_handler(self, data: Dict[str, Any]) -> None:
        try:
            try:
                # 解包消息
                msg_type, seq, sid, nonce, encrypted, tag = unpack_message(data["text"])
            except (binascii.Error, ValueError, KeyError, TypeError):
                return
            if sid not in self.connect_pool:
                if msg_type == MessageType.CONNECT.value:
                    await self._connect_handler(session_id=sid, pkey=encrypted)
                return
            conn_info = self.connect_pool[sid]
            if msg_type == MessageType.CONNECT.value:
                if seq != 0:
                    print(f"[丢弃] 服务端握手包序列号错误 seq={seq}, 应为0")
                    return
                conn_info.connected_confirmed = True
                conn_info.last_active = time.time()
                return
            # 非CONNECT包
            if seq != conn_info.peer_recv_seq + 1:
                print(f"[丢弃] 服务端乱序包 seq={seq}, 期望={conn_info.peer_recv_seq+1}")
                return
            decrypted = conn_info.ecdh.decrypt(nonce, encrypted, tag)
            conn_info.peer_recv_seq = seq
            conn_info.last_active = time.time()
            if msg_type == MessageType.DISCONNECT.value:
                if decrypted == b"Disconnect":
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected", conn_info)
                    del self.connect_pool[sid]
                elif decrypted == b"Disconnected":
                    del self.connect_pool[sid]
                return
            elif msg_type == MessageType.PING.value:
                await self.send_message(MessageType.PONG, b"Pong", conn_info)
                return
            elif msg_type == MessageType.PONG.value:
                return
            elif msg_type == MessageType.MESSAGE.value:
                for callback in self.callbacks:
                    asyncio.create_task(callback(conn_info, decrypted))
            else:
                print(f"未知消息类型: {msg_type}")
        except Exception as e:
            print(f"消息处理异常: {e}")

    async def heartbeat_check(self):
        while True:
            to_remove = []
            for sid, conn in self.connect_pool.copy().items():
                if time.time() - conn.last_active > self.heartbeat_interval:
                    await self.send_message(MessageType.PING, b"Ping", conn)
                if time.time() - conn.last_active > self.heartbeat_interval * 2:
                    to_remove.append(sid)
                    
            for sid in to_remove:
                if sid in self.connect_pool:
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected", self.connect_pool[sid])
                    del self.connect_pool[sid]
                    
            await asyncio.sleep(self.heartbeat_interval)

    async def run(self):
        await self.cli.listen(self.message_page, self._message_handler)
        await self.cli.broadcast(self.index_page, json.dumps({
            "name": self.name,
            "public_key": self.pub_key.export_key(format='PEM'),
            "message_page": self.message_page,
            "version": "0.1.0",
        }, indent=4))
        await asyncio.gather(self.cli.run(), self.heartbeat_check())


class npTLSClient:
    def __init__(self, notepaper: Notepaper, index_page: str, heartbeat_interval: int = 5):
        self.cli: Notepaper = notepaper
        self.priv_key, self.pub_key = generate_key_pair()
        self.ecdh: ECDH | None = None
        self.session_id: str | None = None
        self.message_page: str | None = None
        self.server_pubkey: ECC.EccKey | None = None
        self.send_seq: int = 0  # 修改为从0开始，与服务端一致
        self.peer_recv_seq: int = 0
        self.index_page: str = index_page
        self.connected_event = asyncio.Event()
        self.callbacks: list[Callable[[bytes], Coroutine]] = []
        self.heartbeat_interval = heartbeat_interval
        self._last_active = time.time()
        self._heartbeat_task = None

    def add_handler(self, handler: Callable[[bytes], Coroutine]):
        self.callbacks.append(handler)

    async def _handle_message(self, data):
        try:
            msg_type, seq, sid, nonce, encrypted, tag = unpack_message(data["text"])
            if sid != self.session_id:
                return
            if msg_type == MessageType.CONNECT.value:
                if seq != 0:
                    print(f"[丢弃] 客户端握手包序列号错误 seq={seq}, 应为0")
                    return
                decrypted = self.ecdh.decrypt(nonce, encrypted, tag)
                self._last_active = time.time()
                if decrypted == b"Connected":
                    self.connected_event.set()
                return
            # 非CONNECT包
            if seq != self.peer_recv_seq + 1:
                print(f"[丢弃] 客户端乱序包 seq={seq}, 期望={self.peer_recv_seq+1}")
                return
            decrypted = self.ecdh.decrypt(nonce, encrypted, tag)
            self.peer_recv_seq = seq
            self._last_active = time.time()
            if msg_type == MessageType.DISCONNECT.value:
                if decrypted == b"Disconnect":
                    await self.send_message(MessageType.DISCONNECT, b"Disconnected")
                if decrypted == b"Disconnected":
                    pass
                await self.cleanup() 
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
                print(f"未知消息类型: {msg_type}")
        except Exception as e:
            return

    async def send_message(self, type_: MessageType, data: bytes):
        if not self.connected_event.is_set() and type_ != MessageType.CONNECT:
            raise RuntimeError("Not connected. Call connect() first.")
        if self.ecdh is None or self.session_id is None or self.message_page is None:
            raise RuntimeError("Handshake not completed or missing required attributes.")
        self.send_seq += 1
        seq = self.send_seq
        nonce, encrypted, tag = self.ecdh.encrypt(data)
        msg = pack_message(
            msg_type=type_.value,
            nonce=nonce,
            data=encrypted,
            tag=tag,
            sid=self.session_id,
            seq=seq
        )
        await self.cli.broadcast(self.message_page, msg)
        

    async def _heartbeat_check(self):
        while self.connected_event.is_set():
            if time.time() - self._last_active > self.heartbeat_interval:
                await self.send_message(MessageType.PING, b"Ping")
                
            if time.time() - self._last_active > self.heartbeat_interval * 2:
                await self.send_message(MessageType.DISCONNECT, b"Disconnected")
                await self.cleanup()
                break
                
            await asyncio.sleep(self.heartbeat_interval)

    async def disconnect(self):
        if not self.connected_event.is_set():
            return  # 已经断开，避免重复操作

        try:
            # 发送断开请求
            await self.send_message(MessageType.DISCONNECT, b"Disconnect")
        except Exception as e:
            print(f"发送 DISCONNECT 失败: {e}")
        finally:
            await self.cleanup() 

    async def cleanup(self):
        self.connected_event.clear()
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        await self.cli.close() 
    async def run(self):
        self.connected_event.clear()
        index_raw = await self.cli.get_content(self.index_page)
        index_data = json.loads(index_raw)
        self.server_pubkey = ECC.import_key(index_data["public_key"])
        self.message_page = index_data["message_page"]
        self.ecdh = ECDH(self.priv_key, self.server_pubkey)
        self.session_id = secrets.token_urlsafe(6)
        
        
        await self.cli.broadcast(self.message_page, pack_message(
            msg_type=MessageType.CONNECT.value,
            nonce=bytes(16),
            data=self.pub_key.export_key(format="PEM").encode(),
            tag=bytes(16),
            sid=self.session_id,
            seq=0))
        await self.cli.listen(self.message_page, self._handle_message)
        
        # 启动心跳检测
        self._heartbeat_task = asyncio.create_task(self._heartbeat_check())
        await self.cli.run()