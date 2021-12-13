from __future__ import annotations
from src.austin_heller_repo.socket import ServerSocketFactory, ClientSocket, ClientSocketFactory, Semaphore, get_machine_guid, Encryption, ServerSocket, ClientSocketTimeoutException
from austin_heller_repo.threading import start_thread
import unittest
import time
from datetime import datetime
import threading
from typing import List, Tuple
import os
import base64
import shutil
import tempfile

_port = 28775


class SocketClientFactoryTest(unittest.TestCase):

	def test_initialize_socket_client_0(self):

		_to_client_packet_bytes_length = 4

		def _on_accepted_client_method(client_socket: ClientSocket):
			raise Exception(f"Unexpected client found")

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=1,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)

	def test_start_server_socket_0(self):
		# start server socket and stop

		_to_client_packet_bytes_length = 4

		def _on_accepted_client_method(client_socket: ClientSocket):
			raise Exception(f"Unexpected client found")

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=1,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)
		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)
		_server_socket.stop_accepting_clients()

	def test_connect_sockets_0(self):
		# create accepting socket and transmitting socket

		_to_client_packet_bytes_length = 4
		_to_server_packet_bytes_length = 4

		def _on_accepted_client_method(client_socket: ClientSocket):
			print(f"Connected to client: {client_socket}")
			client_socket.close()

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=1,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)
		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)
		time.sleep(1)
		_client_socket_factory = ClientSocketFactory(
			to_server_packet_bytes_length=_to_server_packet_bytes_length,
			server_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_socket = _client_socket_factory.get_client_socket()
		self.assertIsNotNone(_client_socket)
		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)
		_client_socket.close(
			is_forced=False
		)
		_server_socket.stop_accepting_clients()
		_server_socket.close()

	def test_connect_sockets_1(self):
		# create accepting socket and multiple client sockets

		_to_client_packet_bytes_length = 4
		_to_server_packet_bytes_length = 4
		_clients_total = 10

		def _on_accepted_client_method(client_socket: ClientSocket):
			print(f"Connected to client: {client_socket}")
			client_socket.close(
				is_forced=False
			)

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=_clients_total,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)
		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)
		time.sleep(1)
		_client_socket_factory = ClientSocketFactory(
			to_server_packet_bytes_length=_to_server_packet_bytes_length,
			server_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_sockets = []
		for _client_index in range(_clients_total):
			_client_socket = _client_socket_factory.get_client_socket()
			self.assertIsNotNone(_client_socket)
			_client_sockets.append(_client_socket)
		for _client_index in range(_clients_total):
			_client_sockets[_client_index].connect_to_server(
				ip_address="0.0.0.0",
				port=_port
			)
		for _client_index in range(_clients_total):
			_client_sockets[_client_index].close(
				is_forced=False
			)
		_server_socket.stop_accepting_clients()
		_server_socket.close()

	def test_connect_sockets_2(self):
		# create accepting socket and multiple client sockets but one too many

		_to_client_packet_bytes_length = 4
		_to_server_packet_bytes_length = 4
		_clients_total = 1

		_accepted_client_index = 0
		def _on_accepted_client_method(client_socket: ClientSocket):
			nonlocal _accepted_client_index
			print(f"{_accepted_client_index}: Connected to client at time {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')}: {client_socket}")
			_accepted_client_index += 1
			time.sleep(1)
			client_socket.close(
				is_forced=False
			)

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=_clients_total,
			accept_timeout_seconds=30,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)
		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)
		time.sleep(1)
		_client_socket_factory = ClientSocketFactory(
			to_server_packet_bytes_length=_to_server_packet_bytes_length,
			server_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_sockets = []  # type: List[ClientSocket]
		_client_sockets_threads = []
		_client_sockets_semaphore = Semaphore()

		def _create_client():
			nonlocal _client_sockets_semaphore
			try:
				_client_socket = _client_socket_factory.get_client_socket()
				self.assertIsNotNone(_client_socket)
				_client_socket.connect_to_server(
					ip_address="0.0.0.0",
					port=_port
				)
				_client_sockets_semaphore.acquire()
				_client_sockets.append(_client_socket)
				_client_sockets_semaphore.release()
			except Exception as ex:
				print(f"ex: {ex}")
		for _client_index in range(_clients_total * 100):
			_client_sockets_thread = threading.Thread(target=_create_client)
			_client_sockets_threads.append(_client_sockets_thread)
		for _client_sockets_thread in _client_sockets_threads:
			_client_sockets_thread.start()
		for _client_sockets_thread in _client_sockets_threads:
			_client_sockets_thread.join()
		for _client_index in range(len(_client_sockets)):
			_client_socket = _client_sockets[_client_index]
			_client_socket.close(
				is_forced=False
			)
		_server_socket.stop_accepting_clients()
		_server_socket.close()

	def test_client_messages_0(self):
		# send basic text message from one client to the server

		_to_client_packet_bytes_length = 4
		_to_server_packet_bytes_length = 4

		_server_sockets = []  # type: List[ClientSocket]
		_server_sockets_semaphore = Semaphore()

		def _on_accepted_client_method(client_socket: ClientSocket):
			print(f"Connected to client: {client_socket}")
			_server_sockets_semaphore.acquire()
			_server_sockets.append(client_socket)
			_server_sockets_semaphore.release()

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=1,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)
		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)
		time.sleep(1)
		_client_socket_factory = ClientSocketFactory(
			to_server_packet_bytes_length=_to_server_packet_bytes_length,
			server_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_socket = _client_socket_factory.get_client_socket()
		self.assertIsNotNone(_client_socket)
		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)
		_expected_line = "test"
		_client_socket.write(_expected_line)
		_client_socket.close(
			is_forced=False
		)
		_server_socket.stop_accepting_clients()

		self.assertEqual(1, len(_server_sockets))
		_actual_line = _server_sockets[0].read()
		self.assertEqual(_expected_line, _actual_line)
		_server_sockets[0].close(
			is_forced=False
		)
		_server_socket.close()

	def test_client_messages_1(self):
		# send multiple text messages from one client to the server

		_to_client_packet_bytes_length = 4
		_to_server_packet_bytes_length = 4

		_server_sockets = []  # type: List[ClientSocket]
		_server_sockets_semaphore = Semaphore()

		def _on_accepted_client_method(client_socket: ClientSocket):
			print(f"Connected to client: {client_socket}")
			_server_sockets_semaphore.acquire()
			_server_sockets.append(client_socket)
			_server_sockets_semaphore.release()

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=1,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False,
			is_debug=True
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)
		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)
		time.sleep(1)
		_client_socket_factory = ClientSocketFactory(
			to_server_packet_bytes_length=_to_server_packet_bytes_length,
			server_read_failed_delay_seconds=0.1,
			is_ssl=False,
			is_debug=True
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_socket = _client_socket_factory.get_client_socket()
		self.assertIsNotNone(_client_socket)
		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)
		_expected_lines = ["test", "right", "here"]
		for _expected_line in _expected_lines:
			print(f"writing expected line: {_expected_line}")
			_client_socket.write(_expected_line)
		print(f"closing _client_socket")
		_client_socket.close(
			is_forced=False
		)
		print(f"closed _client_socket")
		_server_socket.stop_accepting_clients()

		self.assertEqual(1, len(_server_sockets))
		for _expected_line in _expected_lines:
			_actual_line = _server_sockets[0].read()
			self.assertEqual(_expected_line, _actual_line)

		_server_sockets[0].close(
			is_forced=False
		)
		_server_socket.close()

	def test_client_messages_2(self):
		# send multiple text messages with unusual characters from one client to the server

		_to_client_packet_bytes_length = 1024 * 3
		_to_server_packet_bytes_length = 1024 * 4
		_server_sockets = []  # type: List[ClientSocket]
		_server_sockets_semaphore = Semaphore()

		def _on_accepted_client_method(client_socket: ClientSocket):
			#print(f"Connected to client: {client_socket}")
			_server_sockets_semaphore.acquire()
			_server_sockets.append(client_socket)
			_server_sockets_semaphore.release()

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=1,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)
		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)
		time.sleep(1)
		_client_socket_factory = ClientSocketFactory(
			to_server_packet_bytes_length=_to_server_packet_bytes_length,
			server_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_socket = _client_socket_factory.get_client_socket()
		self.assertIsNotNone(_client_socket)
		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)
		_server_socket.stop_accepting_clients()

		_expected_lines = ["test", "", "1234567890" * 10**7]
		for _expected_line_index, _expected_line in enumerate(_expected_lines):
			_client_socket.write_async(_expected_line)

		self.assertEqual(1, len(_server_sockets))
		_actual_lines = []

		def _read_callback(text: str):
			_actual_lines.append(text)  # TODO is list.append thread-safe?
		for _expected_line_index in range(len(_expected_lines)):
			_server_sockets[0].read_async(_read_callback)

		print("waiting...")
		time.sleep(1.0)
		while _client_socket.is_writing() or _server_sockets[0].is_reading():
			print(f"_is_writing: {_client_socket.is_writing()} | _is_reading: {_server_sockets[0].is_reading()}")
			time.sleep(0.1)

		print("finished")

		self.assertEqual(3, len(_expected_lines))
		self.assertEqual(3, len(_actual_lines))

		#for _expected_line, _actual_line in zip(_expected_lines, _actual_lines):
		#	print(f"len(_expected_line): {len(_expected_line)}")
		#	print(f"len(_actual_line): {len(_actual_line)}")

		for _expected_line, _actual_line in zip(_expected_lines, _actual_lines):
			self.assertEqual(_expected_line, _actual_line)

		_client_socket.close(
			is_forced=False
		)
		_server_sockets[0].close(
			is_forced=False
		)
		_server_socket.close()

	def test_client_messages_3(self):
		# send massive amount of messages from one client to the server

		_to_client_packet_bytes_length = 1024 * 3
		_to_server_packet_bytes_length = 1024 * 4
		_server_sockets = []  # type: List[ClientSocket]
		_server_sockets_semaphore = Semaphore()

		def _on_accepted_client_method(client_socket: ClientSocket):
			#print(f"Connected to client: {client_socket}")
			_server_sockets_semaphore.acquire()
			_server_sockets.append(client_socket)
			_server_sockets_semaphore.release()

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=1,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)
		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)
		time.sleep(1)
		_client_socket_factory = ClientSocketFactory(
			to_server_packet_bytes_length=_to_server_packet_bytes_length,
			server_read_failed_delay_seconds=0.1,
			is_ssl=False
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_socket = _client_socket_factory.get_client_socket()
		self.assertIsNotNone(_client_socket)
		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)
		_server_socket.stop_accepting_clients()

		_expected_lines = []
		_messages_total = 100000
		for _index in range(_messages_total):
			_expected_lines.append(str(_index))
		for _expected_line_index, _expected_line in enumerate(_expected_lines):
			_client_socket.write_async(_expected_line)

		self.assertEqual(1, len(_server_sockets))
		_actual_lines = []

		def _read_callback(text: str):
			_actual_lines.append(text)  # TODO is list.append thread-safe?
		for _expected_line_index in range(len(_expected_lines)):
			_server_sockets[0].read_async(_read_callback)

		#print("waiting...")
		time.sleep(1.0)
		while _client_socket.is_writing() or _server_sockets[0].is_reading():
			#print(f"_is_writing: {_client_socket.is_writing()} | _is_reading: {_server_sockets[0].is_reading()}")
			time.sleep(0.1)

		#print("finished")

		self.assertEqual(_messages_total, len(_expected_lines))
		self.assertEqual(_messages_total, len(_actual_lines))

		#for _expected_line, _actual_line in zip(_expected_lines, _actual_lines):
		#	print(f"len(_expected_line): {len(_expected_line)}")
		#	print(f"len(_actual_line): {len(_actual_line)}")

		for _expected_line, _actual_line in zip(_expected_lines, _actual_lines):
			self.assertEqual(_expected_line, _actual_line)

		_client_socket.close(
			is_forced=False
		)
		_server_sockets[0].close(
			is_forced=False
		)
		_server_socket.close()

	def test_get_machine_guid_0(self):
		# try to get the same guid from this machine
		_first_guid = get_machine_guid()
		_second_guid = get_machine_guid()
		self.assertEqual(_first_guid, _second_guid)

	def test_encrypted_sockets_0(self):
		# send massive amount of encrypted messages from one client to the server
		_to_client_packet_bytes_length = 1024 * 3
		_to_server_packet_bytes_length = 1024 * 4
		_server_sockets = []  # type: List[ClientSocket]
		_server_sockets_semaphore = Semaphore()
		_encryption = Encryption(
			key=base64.b64decode("2/NjR3Smm5sLFt7EaVgXuMSVrizvp4N2GwZjjFwZbkM=")
		)

		def _on_accepted_client_method(client_socket: ClientSocket):
			# print(f"Connected to client: {client_socket}")
			_server_sockets_semaphore.acquire()
			_server_sockets.append(client_socket)
			_server_sockets_semaphore.release()

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=1,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False,
			encryption=_encryption
		)
		self.assertIsNotNone(_server_socket_factory)
		_server_socket = _server_socket_factory.get_server_socket()
		self.assertIsNotNone(_server_socket)
		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)
		time.sleep(1)
		_client_socket_factory = ClientSocketFactory(
			to_server_packet_bytes_length=_to_server_packet_bytes_length,
			server_read_failed_delay_seconds=0.1,
			is_ssl=False,
			encryption=_encryption
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_socket = _client_socket_factory.get_client_socket()
		self.assertIsNotNone(_client_socket)
		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)
		_server_socket.stop_accepting_clients()

		_expected_lines = []
		_messages_total = 10000
		for _index in range(_messages_total):
			_expected_lines.append(str(_index))
		for _expected_line_index, _expected_line in enumerate(_expected_lines):
			#print(f"writing \"{_expected_line}\"")
			_client_socket.write_async(_expected_line)
			#print(f"wrote \"{_expected_line}\"")

		self.assertEqual(1, len(_server_sockets))
		_actual_lines = []

		def _read_callback(text: str):
			_actual_lines.append(text)  # TODO is list.append thread-safe?

		for _expected_line_index in range(len(_expected_lines)):
			#print(f"reading \"{_expected_lines[_expected_line_index]}\"")
			_server_sockets[0].read_async(_read_callback)
			#print(f"read \"{_expected_lines[_expected_line_index]}\"")

		#print("waiting...")
		time.sleep(1.0)
		while _client_socket.is_writing() or _server_sockets[0].is_reading():
			# print(f"_is_writing: {_client_socket.is_writing()} | _is_reading: {_server_sockets[0].is_reading()}")
			time.sleep(0.1)

		#print("finished")

		self.assertEqual(_messages_total, len(_expected_lines))
		self.assertEqual(_messages_total, len(_actual_lines))

		# for _expected_line, _actual_line in zip(_expected_lines, _actual_lines):
		#	print(f"len(_expected_line): {len(_expected_line)}")
		#	print(f"len(_actual_line): {len(_actual_line)}")

		for _expected_line, _actual_line in zip(_expected_lines, _actual_lines):
			self.assertEqual(_expected_line, _actual_line)

		_client_socket.close(
			is_forced=False
		)
		_server_sockets[0].close(
			is_forced=False
		)
		_server_socket.close()

	def test_upload_and_download_0(self):

		_file_sizes = [
			1024**2,
			1024**2 * 10,
			1,
			0,
			10,
			1024**2 * 100,
			1024**3,
			0,
			1,
			2
		]

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False
		)

		def _client_connected(client_socket: ClientSocket):
			client_socket.upload(_source_temp_file.name)
			client_socket.close(
				is_forced=False
			)

		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_client_connected
		)

		for _file_size in _file_sizes:

			print(f"_file_size: {_file_size}")

			_source_temp_file = tempfile.NamedTemporaryFile(delete=False)
			with open(_source_temp_file.name, "wb") as _file_handle:
				if _file_size > 0:
					_file_handle.seek(_file_size - 1)
					_file_handle.write(bytes(1))

			with open(_source_temp_file.name, "rb") as _file_handle:
				_file_handle.seek(0, 2)
				self.assertEqual(_file_size, _file_handle.tell())

			_client_socket = ClientSocket(
				packet_bytes_length=4096,
				read_failed_delay_seconds=0.1,
				is_ssl=False
			)

			_client_socket.connect_to_server(
				ip_address="0.0.0.0",
				port=_port
			)

			_destination_temp_file = tempfile.NamedTemporaryFile(delete=False)

			_client_socket.download(_destination_temp_file.name)
			_client_socket.close(
				is_forced=False
			)

			with open(_destination_temp_file.name, "rb") as _file_handle:
				_file_handle.seek(0, 2)
				self.assertEqual(_file_size, _file_handle.tell())

			os.unlink(_source_temp_file.name)
			os.unlink(_destination_temp_file.name)

		_server_socket.stop_accepting_clients()
		_server_socket.close()

	def test_socket_timeout_0(self):
		# on_accepted_client_method takes too long

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			client_socket_timeout_seconds=None,
			is_ssl=False,
			is_debug=True
		)

		def _on_accepted_client_method(client_socket: ClientSocket):
			time.sleep(2)
			client_socket.close(
				is_forced=False
			)

		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)

		_client_socket = ClientSocket(
			packet_bytes_length=4096,
			read_failed_delay_seconds=0.1,
			timeout_seconds=1.0,
			is_ssl=False,
			is_debug=True
		)

		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)

		print("writing...")
		_client_socket.write("test 0")
		print("reading...")
		with self.assertRaises(ClientSocketTimeoutException) as _client_socket_timeout_exception_assert_raises_context:
			_client_socket.read()
		print("waiting...")
		time.sleep(1)
		#print("joining...")
		#_client_socket_timeout_exception_assert_raises_context.exception.get_timeout_thread().try_join()
		print("_client_socket closing...")
		#with self.assertRaises(ConnectionResetError):
		_client_socket.close(
			is_forced=False
		)
		print("_server_socket stopping...")
		_server_socket.stop_accepting_clients()
		print("_server_socket closing...")
		_server_socket.close()
		time.sleep(1)

	def test_socket_on_accepted_client_method_exception_0(self):
		# exception occurs in on_accepted_client_method

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			client_socket_timeout_seconds=None,
			is_ssl=False,
			is_debug=True
		)

		def _on_accepted_client_method(client_socket: ClientSocket):
			raise Exception(f"Test")

		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)

		time.sleep(1)

		_client_socket = ClientSocket(
			packet_bytes_length=4096,
			read_failed_delay_seconds=0.1,
			timeout_seconds=1.0,
			is_ssl=False,
			is_debug=True
		)

		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)
		print("waiting...")
		time.sleep(0.5)

		print("writing...")
		with self.assertRaises(BrokenPipeError) as _broken_pipe_error_exception_assert_raises_context:
			_client_socket.write("test 0")
			raise Exception(f"Failed to discover broken pipe in write")
		print("_client_socket closing...")
		_client_socket.close(
			is_forced=False
		)
		print("_server_socket stopping...")
		_server_socket.stop_accepting_clients()
		print("_server_socket closing...")
		_server_socket.close()

	def test_socket_on_accepted_client_method_exception_1(self):
		# exception occurs in on_accepted_client_method and discover on close
		# NOTE this does not throw an exception because no communication occurs once the exception occurs; the server connection closes normally and then this client socket closes right after

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			client_socket_timeout_seconds=None,
			is_ssl=False
		)

		semaphore = Semaphore()
		semaphore.acquire()

		def _on_accepted_client_method(client_socket: ClientSocket):
			nonlocal semaphore
			semaphore.acquire()
			semaphore.release()
			raise Exception(f"Test")

		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)

		_client_socket = ClientSocket(
			packet_bytes_length=4096,
			read_failed_delay_seconds=0.1,
			timeout_seconds=1.0,
			is_ssl=False
		)

		time.sleep(1)

		print("connecting...")

		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)

		print("writing...")
		_client_socket.write("test 0")

		print("releasing semaphore")
		semaphore.release()

		print("waiting...")
		time.sleep(2)

		print("_client_socket closing...")
		with self.assertRaises(AssertionError):
			with self.assertRaises(BrokenPipeError):
				_client_socket.close(
					is_forced=False
				)
		print("_server_socket stopping...")
		_server_socket.stop_accepting_clients()
		print("_server_socket closing...")
		_server_socket.close()

	def test_socket_on_accepted_client_method_exception_2(self):
		# exception occurs in on_accepted_client_method and discover on read

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			client_socket_timeout_seconds=None,
			is_ssl=False,
			is_debug=True
		)

		semaphore = Semaphore()
		semaphore.acquire()

		def _on_accepted_client_method(client_socket: ClientSocket):
			nonlocal semaphore
			semaphore.acquire()
			semaphore.release()
			raise Exception(f"Test")

		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)

		time.sleep(1)

		_client_socket = ClientSocket(
			packet_bytes_length=4096,
			read_failed_delay_seconds=0.1,
			timeout_seconds=1.0,
			is_ssl=False,
			is_debug=True
		)

		print("connecting...")

		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)

		print("writing...")
		_client_socket.write("test 0")

		print("releasing semaphore...")
		semaphore.release()

		print("waiting...")
		time.sleep(1)

		with self.assertRaises(ConnectionResetError):
			print("reading...")
			_client_socket.read()
		print("_client_socket closing...")
		_client_socket.close(
			is_forced=False
		)
		print("_server_socket stopping...")
		_server_socket.stop_accepting_clients()
		print("_server_socket closing...")
		_server_socket.close()

	def test_socket_on_accepted_client_method_exception_3(self):
		# exception occurs in on_accepted_client_method and try to close as fast as possible
		# NOTE the fact that this test passes makes it clear that feedback should be read from the ClientSocket instead of just write-and-forget processes

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			client_socket_timeout_seconds=None,
			is_ssl=False
		)

		def _on_accepted_client_method(client_socket: ClientSocket):
			raise Exception(f"Test")

		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)

		_client_socket = ClientSocket(
			packet_bytes_length=4096,
			read_failed_delay_seconds=0.1,
			timeout_seconds=1.0,
			is_ssl=False
		)

		print("connecting...")

		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)

		print("writing...")
		_client_socket.write("")

		print("_client_socket closing...")
		_client_socket.close(
			is_forced=False
		)
		print("_server_socket stopping...")
		_server_socket.stop_accepting_clients()
		print("_server_socket closing...")
		_server_socket.close()

	def test_upload_and_download_ssl_0(self):

		_file_sizes = [
			1024**2,
			1024**2 * 10,
			1,
			0,
			10,
			1024**2 * 100,
			1024**3,
			0,
			1,
			2
		]

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			is_ssl=True
		)

		def _client_connected(client_socket: ClientSocket):
			client_socket.upload(_source_temp_file.name)
			client_socket.close(
				is_forced=False
			)

		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_client_connected
		)

		for _file_size in _file_sizes:

			print(f"_file_size: {_file_size}")

			_source_temp_file = tempfile.NamedTemporaryFile(delete=False)
			with open(_source_temp_file.name, "wb") as _file_handle:
				if _file_size > 0:
					_file_handle.seek(_file_size - 1)
					_file_handle.write(bytes(1))

			with open(_source_temp_file.name, "rb") as _file_handle:
				_file_handle.seek(0, 2)
				self.assertEqual(_file_size, _file_handle.tell())

			_client_socket = ClientSocket(
				packet_bytes_length=4096,
				read_failed_delay_seconds=0.1,
				is_ssl=True
			)

			_client_socket.connect_to_server(
				ip_address="",
				port=_port
			)

			_destination_temp_file = tempfile.NamedTemporaryFile(delete=False)

			_client_socket.download(_destination_temp_file.name)
			_client_socket.close(
				is_forced=False
			)

			with open(_destination_temp_file.name, "rb") as _file_handle:
				_file_handle.seek(0, 2)
				self.assertEqual(_file_size, _file_handle.tell())

			os.unlink(_source_temp_file.name)
			os.unlink(_destination_temp_file.name)

		_server_socket.stop_accepting_clients()
		_server_socket.close()

	def test_start_reading_then_close(self):

		client_socket = ClientSocket(
			packet_bytes_length=4096,
			read_failed_delay_seconds=0.1,
			is_ssl=False,
			is_debug=True
		)

		server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=1.0,
			client_read_failed_delay_seconds=0.1,
			is_ssl=False,
			is_debug=True
		)

		accepted_client_socket = None  # type: ClientSocket
		def on_accepted_client_method(client_socket: ClientSocket):
			nonlocal accepted_client_socket
			accepted_client_socket = client_socket
			try:
				message = client_socket.read()
				print(f"on_accepted_client_method: message: {message}")
			except Exception as ex:
				print(f"on_accepted_client_method: ex: {ex}")

		server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=36429,
			on_accepted_client_method=on_accepted_client_method
		)

		client_socket.connect_to_server(
			ip_address="",
			port=36429
		)

		def start_reading_thread_method():
			nonlocal client_socket
			try:
				message = client_socket.read()
				print(f"start_reading_thread_method: message: {message}")
			except Exception as ex:
				print(f"start_reading_thread_method: ex: {ex}")

		def close_client_socket_thread_method():
			nonlocal client_socket
			try:
				client_socket.close(
					is_forced=True
				)
				print(f"close_client_socket_thread_method: closed")
			except Exception as ex:
				print(f"close_client_socket_thread_method: ex: {ex}")

		time.sleep(1)

		start_reading_thread = start_thread(start_reading_thread_method)

		time.sleep(1)

		close_client_socket_thread = start_thread(close_client_socket_thread_method)

		time.sleep(1)

		start_reading_thread.join()
		close_client_socket_thread.join()

		server_socket.stop_accepting_clients()
		server_socket.close()

		print(f"closing accepted client socket")
		time.sleep(1)
		accepted_client_socket.close(
			is_forced=True
		)
		print(f"closed accepted client socket")
