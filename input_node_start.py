from input_node import InputNode

input_node = InputNode("127.0.0.2", 8080)
input_node.start()
input_node.connect_to_server('127.0.0.1', 8080)
chain = input_node.get_chain()
for item in chain:
    input_node.extend_chain((item['node']['addr'], item['node']['port']))
print(input_node.send_request((chain[0]['node']['addr'], chain[0]['node']['port']), 'http://www.sustainablesites.org'))
input_node.join()
