import asyncio
import sys
from nptls import npTLSClient,MessageType,Notepaper

async def main():
    cli = Notepaper()
    client = npTLSClient(cli,"nptls-index2")

    async def handle_message(data: bytes):
        print(f"[服务端] {data.decode(errors='ignore')}")

    client.add_handler(handle_message)

    async def user_input_loop():
        while True:
            try:
                text = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                text = text.strip()
                if not text:
                    continue
                if text.lower() == "exit":
                    await client.disconnect()
                    break
                await client.send_message(MessageType.MESSAGE,text.encode())
            except Exception as e:
                raise
    print("正在连接到服务器...")
    asyncio.create_task(client.run())
    await asyncio.wait_for(client.connected_event.wait(),10)
    print("可以输入消息，回车发送。Ctrl+C 退出。")
    await user_input_loop()
if __name__ == "__main__":
    asyncio.run(main())
