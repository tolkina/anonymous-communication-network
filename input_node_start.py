from input_node import InputNode

input_node = InputNode("127.0.0.2", 8080)
input_node.start()
input_node.connect_to_server('127.0.0.1', 8080)
input_node.join()
