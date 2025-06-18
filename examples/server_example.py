from nptls import npTLSServer,MessageType,Notepaper
import asyncio
async def main():
    np=Notepaper()

    nptls = npTLSServer(np, "nptls-index2")
    async def handler(session,data):
        await nptls.send_message(MessageType.MESSAGE,b"echo:"+data,session)

    nptls.add_handler(handler)
    await nptls.run()
if __name__ == "__main__":
    asyncio.run(main())