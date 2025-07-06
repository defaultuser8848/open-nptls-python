import struct
import base64
from typing import Tuple
MAGIC_NUMBER = b"\x6E\x70\x54\x4C"
VERSION = 0x01  
def pack_message(
    msg_type: int,
    nonce: bytes,  # 16 bytes
    data: bytes,
    tag: bytes,    # 16 bytes
    sid: str,      # 8 bytes ASCII
    seq: int
)->str:
    if len(nonce) != 16 or len(tag) != 16 or len(sid) != 8:
        raise ValueError("Invalid parameter lengths")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return base64.a85encode(struct.pack(
        f"<4sBBI8s16s16sI{len(data)}s",  # 修改nonce为16s
        MAGIC_NUMBER,
        VERSION,
        msg_type,
        seq,
        sid.encode('ascii'),
        nonce,
        tag,
        len(data),
        data
    )).decode()

def unpack_message(a85: str) -> Tuple[int, int, str, bytes, bytes, bytes]:
    """二进制解包消息（带魔数校验）"""
    raw=base64.a85decode(a85)
    # 更新最小长度检查 (魔数4 + 版本1 + 类型1 + 序列号4 + SID8 + nonce16 + tag16 + 数据长度4 = 54 bytes)
    if len(raw) < 54:
        raise ValueError("Message too short")
    magic = raw[:4]

    if magic != MAGIC_NUMBER:
        raise ValueError(f"Invalid magic number: {magic.hex()}")

    version = raw[4]
    if version != VERSION:
        raise ValueError(f"Unsupported protocol version: {version}")
    
    # 更新解包格式字符串，nonce改为16s
    msg_type, seq, sid, nonce, tag, data_len = struct.unpack_from("<BI8s16s16sI", raw, 5)
    sid = sid.decode('ascii').rstrip('\x00')
    
    # 更新数据偏移量为54
    expected_len = 54 + data_len
    if len(raw) != expected_len:
        raise ValueError(f"Invalid data length, expected {expected_len}, got {len(raw)}")
    
    data = struct.unpack_from(f"{data_len}s", raw, 54)[0]
    
    return msg_type, seq, sid, nonce, data, tag