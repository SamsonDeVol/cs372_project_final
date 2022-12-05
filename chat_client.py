# Samson DeVol, cs372: Networks Final Project
# Client File

import threading
import sys
import socket
import json

from chatui import init_windows, read_command, print_message, end_windows

HEADER_LEN = 2

def usage():
    print("usage: chat_client.py user host port", file=sys.stderr)

def chat_payload(message):
	json_string = {"type": "chat", "message": message}
	return json.dumps(json_string)

def hello_payload(nickname):
	json_string = {"type": "hello", "nick": nickname}
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
        
def send_threads(s, user):
	"""
	thread for sending messages based on user input
	"""
	while True:
		# read keyboard input
		input_text = read_command(user + "> ")

		if not input_text:
			continue
		
		# special character command
		elif input_text[0] == "/":
			
			# quit client program if user input "/q"
			if input_text == "/q":
				s.close()
				sys.exit(0)

			else:
				continue

		# send input text as a chat payload
		else:
			payload = chat_payload(input_text)
			send_data = build_packet(payload)
			s.sendall(send_data)

def get_next_packet(s):
	"""
	get packet info from socket based on payload size
	return packet
	"""
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
	"""
	decode packet from bytes to get json string
	"""
	data = packet[2:].decode()
	return data

def chat_statement(data):
	return data["nick"] + ": " + data["message"]

def join_statement(data):
	return "*** " + data["nick"] + " has joined the chat"

def leave_statement(data):
	return "*** " + data["nick"] + " has left the chat"

def get_statement(data):
	if data["type"] == "chat":
		return chat_statement(data)
	elif data["type"] == "join":
		return join_statement(data)
	elif data["type"] == "leave":
		return  leave_statement(data)

def rec_threads(s):
	"""
	thread for recieving and printing messages from server
	"""
	while True:
		packet = get_next_packet(s)

		if packet is None:
			break
		
		data = extract_json_string(packet)
		data = json.loads(data)
		
		statement = get_statement(data)
		print_message(statement)

def chat_tui(s, user):
	init_windows()

	# create sending thread
	sending_thread = threading.Thread(target=send_threads, args=(s,user))
	sending_thread.start()

	# create recieving thread
	recieving_thread = threading.Thread(target=rec_threads, args=(s,), daemon=True)
	recieving_thread.start()

	# wait for threads	
	recieving_thread.join()


	end_windows()
	return

def main(argv):
	# parse program start 
	try: 
		user = argv[1]
		host = argv[2]
		port = int(argv[3])
	except:
		usage()
		return 1

	# connect to specified server
	s = socket.socket()
	s.connect((host, port))

	# send hello packet to server
	s.send(build_packet(hello_payload(user)))

	# make client terminal UI 
	chat_tui(s, user)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
