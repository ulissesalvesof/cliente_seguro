"""Framing TCP independente do envelope de controle escolhido pela dupla."""
import asyncio
import struct

from crypto_client import ProtocolError


def pack_frame(body: bytes, maximum: int) -> bytes:
    if not 0 < len(body) <= maximum:
        raise ProtocolError('Comprimento de frame inválido')
    return struct.pack('!I', len(body)) + body


async def read_frame(reader: asyncio.StreamReader, maximum: int, timeout=15) -> bytes:
    async def read():
        prefix = await reader.readexactly(4)
        length = struct.unpack('!I', prefix)[0]
        if not 0 < length <= maximum:
            raise ProtocolError('Comprimento de frame inválido')
        return await reader.readexactly(length)
    try:
        return await asyncio.wait_for(read(), timeout)
    except (asyncio.IncompleteReadError, TimeoutError) as exc:
        raise ProtocolError('Frame incompleto ou timeout; encerrar conexão') from exc


async def write_frame(writer: asyncio.StreamWriter, body: bytes, maximum: int):
    writer.write(pack_frame(body, maximum))
    await writer.drain()
