from middle_node import MiddleNode

middle_node_1 = MiddleNode('127.0.0.3', 9999)
middle_node_1.start()
middle_node_1.connect_to_server('127.0.0.1', 8080)

middle_node_2 = MiddleNode('127.0.0.4', 9999)
middle_node_2.start()
middle_node_2.connect_to_server('127.0.0.1', 8080)

middle_node_3 = MiddleNode('127.0.0.5', 9999)
middle_node_3.start()
middle_node_3.connect_to_server('127.0.0.1', 8080)

middle_node_4 = MiddleNode('127.0.0.6', 9999)
middle_node_4.start()
middle_node_4.connect_to_server('127.0.0.1', 8080)

middle_node_5 = MiddleNode('127.0.0.7', 9999)
middle_node_5.start()
middle_node_5.connect_to_server('127.0.0.1', 8080)

middle_node_1.join()
middle_node_2.join()
middle_node_3.join()
middle_node_4.join()
middle_node_5.join()

# with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#     sock.connect(('127.0.0.1', 9999))
#     sock.sendall(
#         json.dumps({
#             'method': 'create',
#             'params': {
#                 'c1': 0,
#                 'conjugate_braid': [1, 2, 3],
#                 'encrypted_message': 'Ad24r3rfASd34trwf',
#                 'algorithm': 'braid'
#             }
#         }).encode()
#     )
#     res = server_utils.recvall(sock)
#     data = res['data']
#     if data['response'] == 'created':
#         print('OK')
#     else:
#         print('NE OK')
#
# middle_node.stop()
