from __future__ import annotations
from src.austin_heller_repo.socket import ServerSocketFactory, ClientSocket, ClientSocketFactory, Semaphore, get_machine_guid, ThreadDelay, start_thread, Encryption, SemaphoreRequestQueue, SemaphoreRequest, ThreadCycle, CyclingUnitOfWork, PreparedSemaphoreRequest, ThreadCycleCache, ServerSocket, TimeoutThread, ClientSocketTimeoutException
import unittest
import time
from datetime import datetime
import threading
from typing import List, Tuple
import os
import base64
import shutil
import tempfile

_port = 28776


class SocketClientFactoryTest(unittest.TestCase):

	def test_initialize_socket_client_0(self):

		_to_client_packet_bytes_length = 4

		def _on_accepted_client_method(client_socket: ClientSocket):
			raise Exception(f"Unexpected client found")

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=1,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1
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
			client_read_failed_delay_seconds=0.1
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
			client_read_failed_delay_seconds=0.1
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
			server_read_failed_delay_seconds=0.1
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_socket = _client_socket_factory.get_client_socket()
		self.assertIsNotNone(_client_socket)
		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)
		_client_socket.close()
		_server_socket.stop_accepting_clients()
		_server_socket.close()

	def test_connect_sockets_1(self):
		# create accepting socket and multiple client sockets

		_to_client_packet_bytes_length = 4
		_to_server_packet_bytes_length = 4
		_clients_total = 10

		def _on_accepted_client_method(client_socket: ClientSocket):
			print(f"Connected to client: {client_socket}")
			client_socket.close()

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=_clients_total,
			accept_timeout_seconds=0.2,
			client_read_failed_delay_seconds=0.1
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
			server_read_failed_delay_seconds=0.1
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
			_client_sockets[_client_index].close()
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
			client_socket.close()

		_server_socket_factory = ServerSocketFactory(
			to_client_packet_bytes_length=_to_client_packet_bytes_length,
			listening_limit_total=_clients_total,
			accept_timeout_seconds=30,
			client_read_failed_delay_seconds=0.1
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
			server_read_failed_delay_seconds=0.1
		)
		self.assertIsNotNone(_client_socket_factory)
		_client_sockets = []
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
			_client_socket.close()
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
			client_read_failed_delay_seconds=0.1
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
			server_read_failed_delay_seconds=0.1
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
		_client_socket.close()
		_server_socket.stop_accepting_clients()

		self.assertEqual(1, len(_server_sockets))
		_actual_line = _server_sockets[0].read()
		self.assertEqual(_expected_line, _actual_line)
		_server_sockets[0].close()
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
			client_read_failed_delay_seconds=0.1
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
			server_read_failed_delay_seconds=0.1
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
			_client_socket.write(_expected_line)
		print(f"closing _client_socket")
		_client_socket.close()
		print(f"closed _client_socket")
		_server_socket.stop_accepting_clients()

		self.assertEqual(1, len(_server_sockets))
		for _expected_line in _expected_lines:
			_actual_line = _server_sockets[0].read()
			self.assertEqual(_expected_line, _actual_line)

		_server_sockets[0].close()
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
			client_read_failed_delay_seconds=0.1
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
			server_read_failed_delay_seconds=0.1
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

		_client_socket.close()
		_server_sockets[0].close()
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
			client_read_failed_delay_seconds=0.1
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
			server_read_failed_delay_seconds=0.1
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

		_client_socket.close()
		_server_sockets[0].close()
		_server_socket.close()

	def test_get_machine_guid_0(self):
		# try to get the same guid from this machine
		_first_guid = get_machine_guid()
		_second_guid = get_machine_guid()
		self.assertEqual(_first_guid, _second_guid)

	def test_thread_delay_0(self):
		# test starting and stopping multiple times
		_thread_delay = ThreadDelay()
		_is_sleeping = True
		_is_aborting = True
		_abort_seconds = [0.5, 1.5, 0.5]
		_sleep_seconds = [1.0, 1.0, 1.0, 1.0]

		# sleep  ---!-------#---!---!-------#
		# abort  ---#-----------#---#
		#       0   .   1   .   2   .   3

		_expected_abort_outcome = [
			(0.5, True),
			(1.5, True),
			(0.5, True)
		]
		_expected_sleep_outcome = [
			(0.5, False),
			(1.0, True),
			(0.5, False),
			(0.5, False)
		]

		_actual_abort_outcome = []  # type: List[Tuple[float, bool]]
		_actual_sleep_outcome = []  # type: List[Tuple[float, bool]]

		def _sleep():
			for _sleep_index in range(len(_sleep_seconds)):
				#print(f"{_sleep_index}: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')}: sleeping for {_sleep_seconds[_sleep_index]}")
				_start_datetime = datetime.utcnow()
				_is_sleep_completed_normally = _thread_delay.try_sleep(
					seconds=_sleep_seconds[_sleep_index]
				)
				_end_datetime = datetime.utcnow()
				_difference = round((_end_datetime - _start_datetime).total_seconds() * 2)/2
				_actual_sleep_outcome.append((_difference, _is_sleep_completed_normally))
				#print(f"{_sleep_index}: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')}: sleep {_is_sleep_completed_normally}")
				_sleep_index += 1

		def _abort():
			for _abort_index in range(len(_abort_seconds)):
				#print(f"{_abort_index}: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')}: aborting after {_abort_seconds[_abort_index]}")
				_start_datetime = datetime.utcnow()
				time.sleep(_abort_seconds[_abort_index])
				_is_sleep_aborted = _thread_delay.try_abort()
				_end_datetime = datetime.utcnow()
				_difference = round((_end_datetime - _start_datetime).total_seconds() * 2)/2
				_actual_abort_outcome.append((_difference, _is_sleep_aborted))
				#print(f"{_abort_index}: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')}: aborted {_is_sleep_aborted}")
				_abort_index += 1

		_sleep_thread = start_thread(_sleep)
		_abort_thread = start_thread(_abort)

		time.sleep(2.6)

		self.assertEqual(len(_expected_sleep_outcome), len(_actual_sleep_outcome))
		self.assertEqual(len(_expected_abort_outcome), len(_actual_abort_outcome))

		for _index in range(len(_expected_sleep_outcome)):
			self.assertEqual(_expected_sleep_outcome[_index], _actual_sleep_outcome[_index])

		for _index in range(len(_expected_abort_outcome)):
			self.assertEqual(_expected_abort_outcome[_index], _actual_abort_outcome[_index])

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

		_client_socket.close()
		_server_sockets[0].close()
		_server_socket.close()

	def test_semaphore_request_queue_0(self):

		_expected_orders = [
			["first start", "first end", "second start", "third start", "second end", "third end"],
			["first start", "first end", "second start", "third start", "third end", "second end"]
		]

		_actual_orders = []

		for _trial_index in range(100):

			_semaphore_request_queue = SemaphoreRequestQueue(
				acquired_semaphore_names=[]
			)

			_order = []
			_order_semaphore = Semaphore()

			def _first_thread_method():
				_order_semaphore.acquire()
				_order.append("first start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=["test"],
						release_semaphore_names=[]
					)
				)

				_order_semaphore.acquire()
				_order.append("first end")
				_order_semaphore.release()

			def _second_thread_method():
				_order_semaphore.acquire()
				_order.append("second start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=["test"],
						release_semaphore_names=[]
					)
				)

				_order_semaphore.acquire()
				_order.append("second end")
				_order_semaphore.release()

			def _third_thread_method():
				_order_semaphore.acquire()
				_order.append("third start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=[],
						release_semaphore_names=["test"]
					)
				)

				_order_semaphore.acquire()
				_order.append("third end")
				_order_semaphore.release()

			_first_thread = start_thread(_first_thread_method)

			time.sleep(0.05)

			_second_thread = start_thread(_second_thread_method)

			time.sleep(0.05)

			_third_thread = start_thread(_third_thread_method)

			time.sleep(0.05)

			_actual_orders.append(_order)

		for _actual_order in _actual_orders:
			self.assertIn(_actual_order, _expected_orders)

	def test_semaphore_request_queue_1(self):

		_expected_orders = [
			["first start", "second start", "second end", "first end", "third start", "third end"],
			["first start", "second start", "first end", "second end", "third start", "third end"]
		]

		_actual_orders = []

		for _trial_index in range(100):

			_semaphore_request_queue = SemaphoreRequestQueue(
				acquired_semaphore_names=[]
			)

			_order = []
			_order_semaphore = Semaphore()

			def _first_thread_method():
				_order_semaphore.acquire()
				_order.append("first start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=["test"],
						release_semaphore_names=["release"]
					)
				)

				_order_semaphore.acquire()
				_order.append("first end")
				_order_semaphore.release()

			def _second_thread_method():
				_order_semaphore.acquire()
				_order.append("second start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=["release"],
						release_semaphore_names=[]
					)
				)

				_order_semaphore.acquire()
				_order.append("second end")
				_order_semaphore.release()

			def _third_thread_method():
				_order_semaphore.acquire()
				_order.append("third start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=[],
						release_semaphore_names=["test"]
					)
				)

				_order_semaphore.acquire()
				_order.append("third end")
				_order_semaphore.release()

			_first_thread = start_thread(_first_thread_method)

			time.sleep(0.05)

			_second_thread = start_thread(_second_thread_method)

			time.sleep(0.05)

			_third_thread = start_thread(_third_thread_method)

			time.sleep(0.05)

			_actual_orders.append(_order)

		for _actual_order in _actual_orders:
			self.assertIn(_actual_order, _expected_orders)

	def test_semaphore_request_queue_2(self):
		# test swapping of two semaphores

		_expected_orders = [
			["first start", "first end", "second start", "third start", "fourth start", "fourth end", "third end", "fifth start", "fifth end", "second end"],
			["first start", "first end", "second start", "third start", "fourth start", "fourth end", "third end", "fifth start", "second end", "fifth end"],
			["first start", "first end", "second start", "third start", "fourth start", "third end", "fourth end", "fifth start", "fifth end", "second end"],
			["first start", "first end", "second start", "third start", "fourth start", "third end", "fourth end", "fifth start", "second end", "fifth end"]
		]

		_actual_orders = []

		for _trial_index in range(100):

			_semaphore_request_queue = SemaphoreRequestQueue(
				acquired_semaphore_names=[]
			)

			_order = []
			_order_semaphore = Semaphore()

			def _first_thread_method():
				_order_semaphore.acquire()
				_order.append("first start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=["first", "second"],
						release_semaphore_names=[]
					)
				)

				_order_semaphore.acquire()
				_order.append("first end")
				_order_semaphore.release()

			def _second_thread_method():
				_order_semaphore.acquire()
				_order.append("second start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=["first", "second"],
						release_semaphore_names=[]
					)
				)

				_order_semaphore.acquire()
				_order.append("second end")
				_order_semaphore.release()

			def _third_thread_method():
				_order_semaphore.acquire()
				_order.append("third start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=["first"],
						release_semaphore_names=["second"]
					)
				)

				_order_semaphore.acquire()
				_order.append("third end")
				_order_semaphore.release()

			def _fourth_thread_method():
				_order_semaphore.acquire()
				_order.append("fourth start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=[],
						release_semaphore_names=["first"]
					)
				)

				_order_semaphore.acquire()
				_order.append("fourth end")
				_order_semaphore.release()

			def _fifth_thread_method():
				_order_semaphore.acquire()
				_order.append("fifth start")
				_order_semaphore.release()

				_semaphore_request_queue.enqueue(
					semaphore_request=SemaphoreRequest(
						acquire_semaphore_names=[],
						release_semaphore_names=["first"]
					)
				)

				_order_semaphore.acquire()
				_order.append("fifth end")
				_order_semaphore.release()

			_first_thread = start_thread(_first_thread_method)

			time.sleep(0.05)

			_second_thread = start_thread(_second_thread_method)

			time.sleep(0.05)

			_third_thread = start_thread(_third_thread_method)

			time.sleep(0.05)

			_fourth_thread = start_thread(_fourth_thread_method)

			time.sleep(0.05)

			_fifth_thread = start_thread(_fifth_thread_method)

			time.sleep(0.05)

			_actual_orders.append(_order)

		for _actual_order in _actual_orders:
			self.assertIn(_actual_order, _expected_orders)

	def test_thread_cycle_0(self):

		_exceptions = []

		def _on_exception(ex):
			print(f"ex: {ex}")
			_exceptions.append(ex)

		for _trial_index in range(10):

			_order = []
			_order_semaphore = Semaphore()

			_work_queue = [
				0.1,
				0.1,
				0.1
			]
			_work_queue_semaphore = Semaphore()

			class TestCyclingUnitOfWork(CyclingUnitOfWork):

				def __init__(self, *, index: int):
					self.__index = index

				def perform(self, *, try_get_next_work_queue_element_prepared_semaphore_request: PreparedSemaphoreRequest, acknowledge_nonempty_work_queue_prepared_semaphore_request: PreparedSemaphoreRequest) -> bool:
					try_get_next_work_queue_element_prepared_semaphore_request.apply()
					_work_queue_semaphore.acquire()
					_is_successful = False
					if len(_work_queue) != 0:
						_work_queue_element = _work_queue.pop(0)
						time.sleep(_work_queue_element)
						_order_semaphore.acquire()
						_order.append(self.__index)
						_order_semaphore.release()
						_is_successful = True
						acknowledge_nonempty_work_queue_prepared_semaphore_request.apply()
					_work_queue_semaphore.release()
					return _is_successful

			_thread_cycle = ThreadCycle(
				cycling_unit_of_work=TestCyclingUnitOfWork(
					index=0
				),
				on_exception=_on_exception
			)

			time.sleep(0.5)

			self.assertEqual([], _order)

			_thread_cycle.start()

			self.assertEqual([], _order)

			_cycled = _thread_cycle.try_cycle()

			self.assertEqual(True, _cycled)

			time.sleep(0.5)

			self.assertEqual([0, 0, 0], _order)

			_work_queue.extend([
				0.1,
				0.1,
				0.1
			])

			_cycled = _thread_cycle.try_cycle()

			self.assertEqual(True, _cycled)

			_cycled = _thread_cycle.try_cycle()

			self.assertEqual(False, _cycled)

			time.sleep(0.5)

			self.assertEqual([0, 0, 0, 0, 0, 0], _order)

			_thread_cycle.stop()

		self.assertEqual(0, len(_exceptions))

	def test_thread_cycle_cache_0(self):

		_order = []
		_order_semaphore = Semaphore()

		_work_queue = [
			0.1,
			0.1,
			0.1
		]
		_work_queue_semaphore = Semaphore()

		class TestCyclingUnitOfWork(CyclingUnitOfWork):

			def __init__(self, *, index: int):
				super().__init__()

				self.__index = index

			def perform(self, *, try_get_next_work_queue_element_prepared_semaphore_request: PreparedSemaphoreRequest, acknowledge_nonempty_work_queue_prepared_semaphore_request: PreparedSemaphoreRequest) -> bool:
				try_get_next_work_queue_element_prepared_semaphore_request.apply()
				_work_queue_semaphore.acquire()
				_is_successful = False
				if len(_work_queue) != 0:
					_work_queue_element = _work_queue.pop(0)
					time.sleep(_work_queue_element)
					_order_semaphore.acquire()
					_order.append(self.__index)
					_order_semaphore.release()
					_is_successful = True
					acknowledge_nonempty_work_queue_prepared_semaphore_request.apply()
				_work_queue_semaphore.release()
				return _is_successful

		_exceptions = []

		def _on_exception(ex):
			print(f"ex: {ex}")
			_exceptions.append(ex)

		_thread_cycle_cache = ThreadCycleCache(
			cycling_unit_of_work=TestCyclingUnitOfWork(
				index=0
			),
			on_exception=_on_exception
		)

		_is_added = []  # type: List[bool]
		for _index in range(len(_work_queue) + 1):
			_is_added.append(_thread_cycle_cache.try_add())

		self.assertEqual([True, True, True, False], _is_added)

		_thread_cycle_cache.clear()

		self.assertEqual(0, len(_exceptions))

	def test_module_loader_0(self):

		_test_directory_path = "/home/austin/temp/test_socket"

		if True:
			if not os.path.exists(_test_directory_path):
				os.mkdir(_test_directory_path)
			for _file_name in os.listdir(_test_directory_path):
				_file_path = os.path.join(_test_directory_path, _file_name)
				if os.path.isfile(_file_path) or os.path.islink(_file_path):
					os.unlink(_file_path)
				elif os.path.isdir(_file_path):
					shutil.rmtree(_file_path)

		_module_loader = ModuleLoader(
			git_clone_directory_path=_test_directory_path
		)

		_git_clone_url = "https://github.com/AustinHellerRepo/TestDeviceModule"

		_module_loader.load_module(
			git_clone_url=_git_clone_url
		)

		_module_directory_name = _git_clone_url.split("/")[-1]
		_module_file_name = "module.py"

		# need to alter the reference to austin_heller_repo with prefix "src"
		_module_file_path = os.path.join(_test_directory_path, _module_directory_name, _module_file_name)

		with open(_module_file_path, "rt") as _file_handle:
			_file_data = _file_handle.read()
		_file_data = _file_data.replace("austin_heller_repo", "src.austin_heller_repo")
		with open(_module_file_path, "wt") as _file_handle:
			_file_handle.write(_file_data)

		_module = _module_loader.get_module(
			git_clone_url=_git_clone_url,
			module_file_name=_module_file_name,
			module_name=_module_directory_name
		)

		self.assertIsNotNone(_module)

		_instance = _module.ImplementedModule()  # type: Module

		def _on_instance_sent_message(message: str):
			print(f"instance sent: \"{message}\"")

		_instance.set_send_method(
			send_method=_on_instance_sent_message
		)

		self.assertIsNotNone(_instance)

		_instance.start()

		time.sleep(2.1)

		_instance.receive(
			data="from test"
		)

		time.sleep(2.0)

		_instance.stop()

		self.assertEqual("091CEE3D-D683-4B31-ABCE-A0AC568FF14B", _instance.get_purpose_guid())

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
			client_read_failed_delay_seconds=0.1
		)

		def _client_connected(client_socket: ClientSocket):
			client_socket.upload(_source_temp_file.name)
			client_socket.close()

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
				read_failed_delay_seconds=0.1
			)

			_client_socket.connect_to_server(
				ip_address="0.0.0.0",
				port=_port
			)

			_destination_temp_file = tempfile.NamedTemporaryFile(delete=False)

			_client_socket.download(_destination_temp_file.name)
			_client_socket.close()

			with open(_destination_temp_file.name, "rb") as _file_handle:
				_file_handle.seek(0, 2)
				self.assertEqual(_file_size, _file_handle.tell())

			os.unlink(_source_temp_file.name)
			os.unlink(_destination_temp_file.name)

		_server_socket.stop_accepting_clients()
		_server_socket.close()

	def test_timeout_thread_0(self):
		# will timeout

		def _thread_method():
			time.sleep(2.0)

		_timeout_thread = TimeoutThread(
			target=_thread_method,
			timeout_seconds=1.0
		)

		_timeout_thread.start()

		_wait_is_successful = _timeout_thread.try_wait()

		self.assertFalse(_wait_is_successful)

		_join_is_successful = _timeout_thread.try_join()

		self.assertEqual(_wait_is_successful, _join_is_successful)

	def test_timeout_thread_1(self):
		# will not timeout

		def _thread_method():
			time.sleep(1.0)

		_timeout_thread = TimeoutThread(
			target=_thread_method,
			timeout_seconds=2.0
		)

		_timeout_thread.start()

		_wait_is_successful = _timeout_thread.try_wait()

		self.assertTrue(_wait_is_successful)

		_join_is_successful = _timeout_thread.try_join()

		self.assertEqual(_wait_is_successful, _join_is_successful)

	def test_timeout_thread_2(self):
		# will be on the line between timeout or not

		def _thread_method():
			time.sleep(0.099)

		_outcomes = []
		for _index in range(100):
			_timeout_thread = TimeoutThread(
				target=_thread_method,
				timeout_seconds=0.1
			)

			_timeout_thread.start()

			_wait_is_successful = _timeout_thread.try_wait()

			_outcomes.append(_wait_is_successful)

			_join_is_successful = _timeout_thread.try_join()

			self.assertEqual(_wait_is_successful, _join_is_successful)

		_is_successful_true_total = len([_outcome for _outcome in _outcomes if _outcome])
		_is_successful_false_total = len([_outcome for _outcome in _outcomes if not _outcome])
		print(f"True: {_is_successful_true_total}, False: {_is_successful_false_total}")

		self.assertGreater(_is_successful_true_total, _is_successful_false_total)

	def test_socket_timeout_0(self):
		# on_accepted_client_method takes too long

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			client_socket_timeout_seconds=None
		)

		def _on_accepted_client_method(client_socket: ClientSocket):
			time.sleep(2)
			client_socket.close()

		_server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=_port,
			on_accepted_client_method=_on_accepted_client_method
		)

		_client_socket = ClientSocket(
			packet_bytes_length=4096,
			read_failed_delay_seconds=0.1,
			timeout_seconds=1.0
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
		print("joining...")
		with self.assertRaises(ConnectionResetError):
			_client_socket_timeout_exception_assert_raises_context.exception.get_timeout_thread().try_join()
		print("_client_socket closing...")
		_client_socket.close()
		print("_server_socket stopping...")
		_server_socket.stop_accepting_clients()
		print("_server_socket closing...")
		_server_socket.close()

	def test_socket_on_accepted_client_method_exception_0(self):
		# exception occurs in on_accepted_client_method

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			client_socket_timeout_seconds=None
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
			timeout_seconds=1.0
		)

		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)
		print("waiting...")
		time.sleep(0.5)

		print("writing...")
		_client_socket.write("test 0")
		with self.assertRaises(BrokenPipeError) as _broken_pipe_error_exception_assert_raises_context:
			_client_socket.read()
		print("_client_socket closing...")
		_client_socket.close()
		print("_server_socket stopping...")
		_server_socket.stop_accepting_clients()
		print("_server_socket closing...")
		_server_socket.close()

	def test_socket_on_accepted_client_method_exception_1(self):
		# exception occurs in on_accepted_client_method and discover on close

		_server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=0.1,
			client_read_failed_delay_seconds=0.1,
			client_socket_timeout_seconds=None
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
			timeout_seconds=1.0
		)

		print("connecting...")

		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)

		print("waiting...")
		time.sleep(1)

		print("writing...")
		_client_socket.write("test 0")
		print("_client_socket closing...")
		with self.assertRaises(BrokenPipeError):
			_client_socket.close()
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
			client_socket_timeout_seconds=None
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
			timeout_seconds=1.0
		)

		print("connecting...")

		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)

		print("waiting...")
		time.sleep(1)

		print("writing...")
		_client_socket.write("test 0")
		print("reading...")
		with self.assertRaises(BrokenPipeError) as _broken_pipe_error_exception_assert_raises_context:
			_client_socket.read()
		print("_client_socket closing...")
		_client_socket.close()
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
			client_socket_timeout_seconds=None
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
			timeout_seconds=1.0
		)

		print("connecting...")

		_client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=_port
		)

		print("writing...")
		_client_socket.write("")

		print("_client_socket closing...")
		_client_socket.close()
		print("_server_socket stopping...")
		_server_socket.stop_accepting_clients()
		print("_server_socket closing...")
		_server_socket.close()


