import socketio
import httpx
import asyncio

class Notepaper():
    def __init__(self, host="https://note.ect.fyi"):
        self.host = host
        self.client = socketio.AsyncClient()
        self._connected = False
        self.callbacks={}
    async def connect(self):
        if not self._connected:
            await self.client.connect(self.host, namespaces=['/note-ws'], transports=['websocket'])
            self._connected = True

    async def broadcast(self, page, data):
        await self.connect()
        await self.client.emit('text_post', {
            'page': page,
            'text': data
        }, namespace='/note-ws')

    async def listen(self, page, callback):
        await self.connect()
        await self.client.call('join', {
            'page': page
        }, namespace='/note-ws')
        self.callbacks[page] = callback
    
    async def get_content(self, page):
        async with httpx.AsyncClient() as session:
            resp=await session.get(f"{self.host}/{page}?t")
            return resp.text

    async def make_share(self, page):
        async with httpx.AsyncClient() as session:
            resp=await session.get(f"{self.host}/s/make/{page}",follow_redirects=True)
            return str(resp.url).split('/')[-1]

    async def run(self):
        async def handler(data):
            page = data['page']
            if page in self.callbacks:
                ret=self.callbacks[page](data)
                if asyncio.iscoroutine(ret):
                    await ret
        self.client.on('text_broadcast', handler, namespace='/note-ws')
        await self.connect()
        await self.client.wait()

    async def close(self):
        if self._connected:
            await self.client.disconnect()
            self._connected = False
