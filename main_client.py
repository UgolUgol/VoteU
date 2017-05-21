from Zclient import Client
from blank import Blank
import json

cl = Client()
while True:
    cmd = input()
    if cmd == 'reg':
        cl.registration()
    if cmd == 'vote':
        cl.vote()
    if cmd == 'status':
        cl.get_server_status()
    if cmd == 'send-sckey':
        cl.send_sckey()
    if cmd == 'results':
        if cl.get_results() == 'send_result':
            cl.exit()
            break
    if cmd == 'help':
        cl.print_help()
    if cmd == 'exit':
        print(cl.exit())
        break