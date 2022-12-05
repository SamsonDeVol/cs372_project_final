# Samson DeVol, cs372: Networks Final Project
# Server File

import sys
import socket
import select
import json

HEADER_LEN = 2

def usage():
	print("usage: server.py port", file=sys.stderr)

def chat_payload(nickname, message):
	json_string = {"type": "chat", "nick": nickname, "message": message}
	return json.dumps(json_string)

def join_payload(nickname):
	json_string = {"type": "join", "nick": nickname}
	return json.dumps(json_string)

def leave_payload(nickname):
	json_string = {"type": "leave", "nick": nickname}
	return json.dumps(json_string)

def build_packet(payload):
	"""
	take json payload and 
	return packet with 2 header bytes to contain buffer size
	"""
	packet = b''
	data_bytes = payload.encode()
	data_len = len(payload)
	len_bytes = data_len.to_bytes(HEADER_LEN, "big")
	packet += len_bytes + data_bytes
	return packet

def broadcast(statement, clients):
	for reciever in clients:
		reciever.sendall(statement)

def get_next_packet(s):
		packet_buffer = b''
		packet = b''

		while True:
			# get packet length w/ bits = HEADER_LEN value
			end_of_packet = int.from_bytes(packet_buffer[0:HEADER_LEN], byteorder="big")
			# if end_of_packet is not null and has enough bits to capture whole word
			if end_of_packet != 0 and end_of_packet + HEADER_LEN <= len(packet_buffer):
				# save word_packet to own variable and drop from packet_buffer
				packet = packet_buffer[:end_of_packet + HEADER_LEN]
				packet_buffer = packet_buffer[end_of_packet + HEADER_LEN:]
				break

			chunk = s.recv(5)

			if chunk == b'':
				return None

			packet_buffer += chunk
			
		return packet

def extract_json_string(packet):
    data = packet[2:].decode()
    return data

def get_packet_data(s):
	# recv() the data from the socket
	packet = get_next_packet(s)
	if not packet:
		return None
	data = extract_json_string(packet)
	data = json.loads(data)
	return data

def run_server(port):
# add the listener socket to the set
	s = socket.socket()
	s.bind(("", port))
	s.listen()
	ready_set = [s]

	# make buffer dict
	socket_to_buffer = {}

	# main loop:
	while True: 
		# call select() and get the sockets that are ready to read
		ready_to_read, _, _ = select.select(ready_set, {}, {})

		# for all sockets that are ready to read:
		for ready_socket in ready_to_read:
            
			# if the ready_socket is the listener ready_socket:
			if ready_socket is s:
                
				# accept() a new connection
				client_connection,_ = s.accept()

				# add the new socket to our set!
				ready_set.append(client_connection)

            #  else the socket is a regular socket:
			else:
                # recv() the data from the socket
				data = get_packet_data(ready_socket)

			    # if you receive zero bytes, disconnect client
				if not data:
					name = socket_to_buffer.pop(ready_socket)
					payload = leave_payload(name)
					statement = build_packet(payload)
					broadcast(statement, socket_to_buffer)
					
					# remove the socket from the set
					ready_set.remove(ready_socket)
					ready_socket.close()
					socket_to_buffer

				# else send join or chat payload to all clients
				else: 	
					if data["type"] == "hello":
						socket_to_buffer[ready_socket] = data["nick"]

						payload = join_payload(socket_to_buffer[ready_socket])
						statement = build_packet(payload)
						broadcast(statement, socket_to_buffer)

					elif data["type"] == "chat":
						payload = chat_payload(socket_to_buffer[ready_socket], data["message"])
						statement = build_packet(payload)
						broadcast(statement, socket_to_buffer)

def main(argv):
    try:
        port = int(argv[1])
    except:
        usage()
        return 1

    run_server(port)

if __name__ == "__main__":
	sys.exit(main(sys.argv))
