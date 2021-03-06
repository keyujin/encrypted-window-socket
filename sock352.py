# main libraries
import binascii
import sys
import socket as syssock
import struct

# encryption libraries 
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame 
from inspect import currentframe, getframeinfo

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the ports to use for the sock352 messages 
global sock352portTx
global sock352portRx

# the public and private keychains in hex format 
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format 
global publicKeys
global privateKeys

# the encryption flag 
global ENCRYPT

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}

# this is 0xEC 
ENCRYPT = 236

global IS_ENCRYPTED
IS_ENCRYPTED = 0b01

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

# jak451 - Jake Karasik
# bk375 - Benjamin Ker

def init(UDPportTx, UDPportRx):  # initialize your UDP socket here

	# Initialize UDP socket
	global MAIN_SOCKET
	MAIN_SOCKET = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)

	# Save recv port for server binding
	global sock352portRx, sock352portTx
	sock352portRx = int(UDPportRx)
	sock352portTx = int(UDPportTx)

	# Header Default Structure & Values
	global PKT_HEADER_DATA, PKT_HEADER_FMT, HEADER_LEN, VERSION, OPT_PTR, PROTOCOL, SRC_PORT, DEST_PORT, WINDOW, CHECKSUM
	PKT_HEADER_FMT = '!BBBBHHLLQQLL'
	PKT_HEADER_DATA = struct.Struct(PKT_HEADER_FMT)
	HEADER_LEN = struct.calcsize(PKT_HEADER_FMT)
	VERSION = 0x1
	OPT_PTR = 0
	PROTOCOL = 0
	SRC_PORT = 0
	DEST_PORT = 0
	WINDOW = 0
	CHECKSUM = 0

	# Flags
	global SYN, FIN, ACK, RES, OPT
	SYN = 0b00000001
	FIN = 0b00000010
	ACK = 0b00000100
	RES = 0b00001000
	OPT = 0b00010000

	# Connection is set?
	global CONNECTION_SET
	CONNECTION_SET = False

	# Remaining window capacity
	global window_size
	window_size = 32000

	# Maximum window capacity
	global max_window_size
	max_window_size = 32000

	# Queue for server
	global queue
	queue = ""

# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
	global publicKeysHex
	global privateKeysHex
	global publicKeys
	global privateKeys

	if (filename):
		try:
			keyfile_fd = open(filename, "r")
			for line in keyfile_fd:
				words = line.split()
				# check if a comment
				# more than 2 words, and the first word does not have a
				# hash, we may have a valid host/key pair in the keychain
				if ((len(words) >= 4) and (words[0].find("#") == -1)):
					host = words[1]
					port = words[2]
					keyInHex = words[3]
					if (words[0] == "private"):
						privateKeysHex[(host, port)] = keyInHex
						privateKeys[(host, port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
					elif (words[0] == "public"):
						publicKeysHex[(host, port)] = keyInHex
						publicKeys[(host, port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
		except Exception, e:
			print ("error: opening keychain file: %s %s" % (filename, repr(e)))
	else:
		print ("error: No filename presented")
	return (publicKeys, privateKeys)


class socket:

	def __init__(self):
		pass

	def bind(self, address):
		MAIN_SOCKET.bind(('', sock352portRx))

	def connect(self, *args):

		# Get globals
		global ENCRYPT
		global address

		# Check if encryption has been requested
		if (len(args) >= 1):
			address = args[0]
		if (len(args) >= 2):
			if (args[1] == ENCRYPT):
				self.encrypt = True
		else:
			self.encrypt = False

		# Set up encryption if requested
		if self.encrypt:
			self.nonce = nacl.utils.random(Box.NONCE_SIZE)
			# Check if host entry exists in privatekeys otherwise use generic ("*","*"")
			if (("localhost", sock352portTx) in privateKeys):
				private_key = privateKeys[("localhost", sock352portTx)]
			else:
				private_key = privateKeys[("*", "*")]
			# Create box with local private key and public key of server
			server_addr = (address[0], str(sock352portTx))
			self.client_box = Box(private_key, publicKeys[server_addr])

		# Connect to server address
		MAIN_SOCKET.connect((address[0], sock352portTx))

		# Create SYN header (random seq_num)
		seq_num = 19
		ack_num = seq_num + 1
		payload_len = 0
		syn_header = PKT_HEADER_DATA.pack(VERSION,
										  SYN,
										  OPT_PTR,
										  PROTOCOL,
										  HEADER_LEN,
										  CHECKSUM,
										  SRC_PORT,
										  DEST_PORT,
										  seq_num,
										  ack_num,
										  WINDOW,
										  payload_len)

		# Set timeout to 0.2 seconds
		MAIN_SOCKET.settimeout(0.2)

		done = False
		response = []
		bytesreceived = 0

		# Attempt to resend up to 5 times
		for i in range(0, 5):

			if (done):
				break

			# Attempt to send SYN packet A
			try:
				MAIN_SOCKET.sendall(syn_header)
			except syssock.error:
				print("Failed to send SYN packet A")
				continue

			while not done:
				try:
					# Receive SYN ACK packet B
					data = MAIN_SOCKET.recv(HEADER_LEN)

					# Append packet to response array
					response.append(data)

					# Add size of packet to bytes received
					bytesreceived += len(data)

					# Check if done receiving
					if (bytesreceived == HEADER_LEN):
						done = True
						break
				except syssock.timeout:
					# Resend on timeout
					print("Request timed out, resending")
					i += 1
					break
				except syssock.error:
					print("Failed to send/receive, trying again")
					i += 1
					break

		# Check if header successfully received
		if (bytesreceived != HEADER_LEN):
			print("Failed to receive.")
			return

		# Put packets together
		response = "".join(response)
		response_as_struct = struct.unpack(PKT_HEADER_FMT, response)

		# Check correct response
		if (response_as_struct[1] != SYN | ACK and response_as_struct[1] != RES):
			print("Error: Received packet is not SYN-ACK or RES")

		# Notify RESET flag received
		if (response_as_struct[1] == RES):
			print("Notice: RESET flag received")

		# Create SYN-ACK header
		new_seq_num = response_as_struct[9]
		new_ack_num = response_as_struct[8] + 1
		ack_header = PKT_HEADER_DATA.pack(VERSION,
										  SYN | ACK,
										  OPT_PTR,
										  PROTOCOL,
										  HEADER_LEN,
										  CHECKSUM,
										  SRC_PORT,
										  DEST_PORT,
										  new_seq_num,
										  new_ack_num,
										  WINDOW,
										  payload_len)

		# Attempt to send ACK packet C
		try:
			MAIN_SOCKET.sendall(ack_header)
		except syssock.error:
			print("Failed to send ACK packet C")

	def listen(self, backlog):
		return

	def accept(self, *args):

		# Get globals
		global ENCRYPT
		global client_addr
		global CONNECTION_SET

		# Check for encryption option
		if (len(args) >= 1):
			if (args[0] == ENCRYPT):
				self.encryption = True
		else:
			self.encryption = False

		# recv SYN A
		(data, address) = MAIN_SOCKET.recvfrom(HEADER_LEN)
		client_addr = address

		# Get client's public key
		if self.encryption:
			if (("localhost", sock352portTx) in privateKeys):
				private_key = privateKeys[("localhost", sock352portTx)]
			else:
				private_key = privateKeys[("*", "*")]

			client_addr = (address[0], str(sock352portTx))
			if (client_addr in publicKeys):
				client_public_key = publicKeys[client_addr]
			else:
				client_public_key = publicKeys[("localhost", str(sock352portTx))]
			self.server_box = Box(private_key, client_public_key)

		# Check is valid SYN
		recv_header = struct.unpack(PKT_HEADER_FMT, data)

		# Warn if invalid packet received
		if (recv_header[1] != SYN):
			print("Error: Received packet is not SYN")

		# Create SYN header
		seq_num = 29  # random number
		ack_num = recv_header[8] + 1  # client seq_num + 1
		payload_len = 0

		# If there is an existing connection, the RESET flag is set.
		flags = SYN | ACK if not CONNECTION_SET else RES

		# Create SYN ACK B
		syn_header = PKT_HEADER_DATA.pack(VERSION,
										  flags,
										  OPT_PTR,
										  PROTOCOL,
										  HEADER_LEN,
										  CHECKSUM,
										  SRC_PORT,
										  DEST_PORT,
										  seq_num,
										  ack_num,
										  WINDOW,
										  payload_len)

		try:
			MAIN_SOCKET.sendto(syn_header, address)
		except syssock.error:
			print("Failed to send SYN ACK B")

		# recv SYN-ACK C
		(data, address) = MAIN_SOCKET.recvfrom(HEADER_LEN)

		# Mark connection as set
		CONNECTION_SET = True

		return (self, address)

	def close(self):

		fin_header = PKT_HEADER_DATA.pack(VERSION,
										  FIN,
										  OPT_PTR,
										  PROTOCOL,
										  HEADER_LEN,
										  CHECKSUM,
										  SRC_PORT,
										  DEST_PORT,
										  0,
										  0,
										  WINDOW,
										  0)

		ack_header = PKT_HEADER_DATA.pack(VERSION,
										  ACK,
										  OPT_PTR,
										  PROTOCOL,
										  HEADER_LEN,
										  CHECKSUM,
										  SRC_PORT,
										  DEST_PORT,
										  0,
										  0,
										  WINDOW,
										  0)

		try:
			MAIN_SOCKET.sendall(fin_header)

			(resp, address) = MAIN_SOCKET.recvfrom(HEADER_LEN)

			recv_header = struct.unpack(PKT_HEADER_FMT, resp)

			if (recv_header[1] != ACK or recv_header[1] != FIN):
				print("Error: Attempted to close but no ACK/FIN received.")
				print recv_header[1]
				return

			MAIN_SOCKET.sendall(ack_header)
		except syssock.error:
			# Timed out waiting for ACK/FIN
			pass

		MAIN_SOCKET.close()

		global CONNECTION_SET
		CONNECTION_SET = False

	def send(self, buffer):

		# Get globals
		global window_size
		global ack

		# Define default payload size
		default_packet_size = 2048

		# Initialize header properties
		flags = 0
		seq_num = 0
		fragment_len = len(buffer)
		highest_ack_num = 0
		if self.encrypt:
			opts = IS_ENCRYPTED
		else:
			opts = 0

		# Set timeout to 0.2 seconds
		MAIN_SOCKET.settimeout(0.2)

		# Start sending segments of the fragment
		while seq_num < fragment_len:

			# Get range of bytes to send
			if seq_num + default_packet_size >= fragment_len:
				end_dist = fragment_len
			else:
				end_dist = seq_num + default_packet_size

			# Calculate size of our payload
			payload_len = end_dist - seq_num

			# Create header and send our packet
			header = PKT_HEADER_DATA.pack(VERSION,
										  flags,
										  opts,
										  PROTOCOL,
										  HEADER_LEN,
										  CHECKSUM,
										  SRC_PORT,
										  DEST_PORT,
										  seq_num,
										  0,
										  WINDOW,
										  payload_len)

			# Encrypt and preempt size increase
			if self.encrypt:
				payload = self.client_box.encrypt(buffer[seq_num:end_dist], self.nonce)
				seq_num -= 40
			else:
				payload = buffer[seq_num:end_dist]

			MAIN_SOCKET.send(header + payload)

			try:
				# Receive ACK and unpack metadata
				ack = MAIN_SOCKET.recv(HEADER_LEN)
			except syssock.error:
				print("Error: send() failed")
				return seq_num

			unpacked_ack = struct.unpack(PKT_HEADER_FMT, ack)
			window_size = unpacked_ack[10]

			# Update ACK number if necessary
			if unpacked_ack[9] > highest_ack_num:
				highest_ack_num = unpacked_ack[9]
				seq_num = highest_ack_num

			while window_size == 0:
				try:
					# Receive ACK and unpack metadata
					ack = MAIN_SOCKET.recv(HEADER_LEN)
				except syssock.error:
					print("Error: send() failed")

				unpacked_ack = struct.unpack(PKT_HEADER_FMT, ack)
				window_size = unpacked_ack[10]

		return seq_num

	def recv(self, nbytes):

		# Get globals
		global data
		global queue
		global address
		global window_size
		global CONNECTION_SET

		# Check for closed connection
		if CONNECTION_SET == False:
			# Get data left from queue and return
			to_return = queue[:nbytes]
			queue = queue[nbytes:]
			return to_return

		if window_size == 0:
			to_return = queue[:nbytes]
			queue = queue[nbytes:]
			window_size = nbytes
			# Send header indicating queue is full
			header = PKT_HEADER_DATA.pack(VERSION,
										  ACK,
										  OPT_PTR,
										  PROTOCOL,
										  HEADER_LEN,
										  CHECKSUM,
										  SRC_PORT,
										  DEST_PORT,
										  0,
										  window_size,
										  window_size,
										  0)
			MAIN_SOCKET.sendto(header, address)
			return to_return

		# Try to receive data from client
		try:
			(data, address) = MAIN_SOCKET.recvfrom(max_window_size)
		except syssock.error:
			print("Error: recv() failed")
			return ""

		# Separate header and actual data (delivery), unpack header
		delivery = data[HEADER_LEN:]
		header = struct.unpack(PKT_HEADER_FMT, data[:HEADER_LEN])
		# Check for encryption modifier
		if header[2] == IS_ENCRYPTED:
			delivery = self.server_box.decrypt(delivery)
		# Check for close message
		if header[1] == FIN:
			# Get data to return and set connection to False
			to_return = queue[:nbytes]
			queue = queue[nbytes:]
			CONNECTION_SET = False
			return to_return

		# If we don't have space for entire delivery
		if len(delivery) > window_size:
			# Put from start of delivery to remaining window size
			queue = queue + delivery[:(window_size + nbytes)]
			ack_num = header[8] + window_size + nbytes
			window_size = 0

			# Send header indicating queue is full
			header = PKT_HEADER_DATA.pack(VERSION,
										  ACK,
										  OPT_PTR,
										  PROTOCOL,
										  HEADER_LEN,
										  CHECKSUM,
										  SRC_PORT,
										  DEST_PORT,
										  0,
										  ack_num,
										  window_size,
										  0)
			MAIN_SOCKET.sendto(header, address)

		else:
			# Put entire delivery and calculate remaining size
			queue = queue + delivery
			window_size = window_size - len(delivery) + nbytes

			# Gets sequence number and assigns to ack_num
			ack_num = header[8] + len(delivery)

			# Create header
			header = PKT_HEADER_DATA.pack(VERSION,
										  ACK,
										  OPT_PTR,
										  PROTOCOL,
										  HEADER_LEN,
										  CHECKSUM,
										  SRC_PORT,
										  DEST_PORT,
										  0,
										  ack_num,
										  window_size,
										  0)
			MAIN_SOCKET.sendto(header, address)

		# Get data and return
		to_return = queue[:nbytes]
		queue = queue[nbytes:]
		return to_return