import unittest
from src.austin_heller_repo.socket import ClientSocketFactory, ServerSocketFactory, ClientSocket
from datetime import datetime
import time
from typing import List, Tuple, Dict, Callable, Type


def get_default_host_address() -> str:
	return "0.0.0.0"


def get_default_host_port() -> int:
	return 32622


def get_default_client_socket_factory() -> ClientSocketFactory:
	return ClientSocketFactory(
		to_server_packet_bytes_length=4096,
		server_read_failed_delay_seconds=0,
		is_ssl=True
	)


def get_default_server_socket_factory() -> ServerSocketFactory:
	return ServerSocketFactory(
		to_client_packet_bytes_length=4096,
		listening_limit_total=10,
		accept_timeout_seconds=1.0,
		client_read_failed_delay_seconds=0,
		is_ssl=True
	)


class TestSsl(unittest.TestCase):

	def test_initialize(self):

		client_socket = get_default_client_socket_factory().get_client_socket()

		self.assertIsNotNone(client_socket)

		server_socket = get_default_server_socket_factory().get_server_socket()

		self.assertIsNotNone(server_socket)

	def test_connection(self):

		server_socket = get_default_server_socket_factory().get_server_socket()

		def on_accepted_client_method(client_socket: ClientSocket):
			print(f"{datetime.utcnow()}: on_accepted_client_method: start")
			time.sleep(1)
			client_socket.close()
			print(f"{datetime.utcnow()}: on_accepted_client_method: end")

		server_socket.start_accepting_clients(
			host_ip_address=get_default_host_address(),
			host_port=get_default_host_port(),
			on_accepted_client_method=on_accepted_client_method
		)

		time.sleep(1)

		client_socket = get_default_client_socket_factory().get_client_socket()

		client_socket.connect_to_server(
			ip_address=get_default_host_address(),
			port=get_default_host_port()
		)

		time.sleep(0.5)

		client_socket.close()

		time.sleep(2)

		server_socket.stop_accepting_clients()

		server_socket.close()

		time.sleep(5)
