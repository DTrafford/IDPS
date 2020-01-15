from channels.generic.websocket import WebsocketConsumer
import json
from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer, AsyncWebsocketConsumer, AsyncConsumer
from .packetTracer.sniffer import ids
from scapy.all import *

class Sniffer:
    class __Sniffer:
        def __init__(self, consumer):
            self.consumer = consumer
            self.sniffer = AsyncSniffer(iface="en0", prn=ids().sniffPackets(self.consumer))

        def start(self):
            self.sniffer.start()

        def stop(self):
            self.sniffer.stop()

    instance = None

    def __init__(self, consumer):
        if not Sniffer.instance:
            Sniffer.instance = Sniffer.__Sniffer(consumer)
        else:
            Sniffer.instance.consumer = consumer
    def __getattr__(self, name):
        return getattr(self.instance, name)
class IDPSConsumer(WebsocketConsumer):

    def connect(self):
        self.accept()

    def disconnect(self, close_code):
        pass

    def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        print('MESSAGE IN RECEIVE = ', message)
        # sniffer = AsyncSniffer(iface="en0", prn=ids().sniffPackets(self))
        sniffer = Sniffer(self)
        if message == "start":
            # async_to_sync(self.channel_layer.group_send)(
            #     self.room_group_name,
            #     {
            #         'type': 'send_notify',
            #         'notify': "Started capture of packet sniffer"
            #     }
            # )

            # sniffer = AsyncSniffer(iface="en0", prn=ids().sniffPackets(self))
            sniffer.start()
            # time.sleep(10)
            # print("Stopping sniffer")
            # sniffer.stop()
    
        if message == "stop":
            print("stopping capturing thread")
            # async_to_sync(self.channel_layer.group_send)(
            #     self.room_group_name,
            #     {
            #         'type': 'send_notify',
            #         'notify': "Stopping capturing thread of packet sniffer"
            #     }
            # )
            sniffer.stop()

    def stopfilter(self, e):
        return self.stopSniff

    def send_message(self, event):
        message = event['message']

        # Send message to WebSocket
        self.send(text_data=json.dumps({
            'message': message
        }))

    def send_notify(self, event):
        message = event['notify']

        # Send message to WebSocket
        self.send(text_data=json.dumps({
            'notify': message
        }))
