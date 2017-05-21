from Zserver import Server
import sys


sv = Server()
sv.configure_server()
sv.run_server(count=int(sys.argv[1]))
