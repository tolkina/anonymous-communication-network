from server import Server

server = Server()
server.start()
server.join()

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#     sock.connect((chain[0]['addr'], chain[1]['port']))
#     sock.sendall(json.dumps({
#         "method": "get_groups",
#         "params": {}
#     }).encode())
#     res = recvall(sock)
#     print(res)
#
# server.stop()
