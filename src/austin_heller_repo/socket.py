print("socket.py: loading: start")

from austin_heller_repo.threading import Semaphore, TimeoutThread, start_thread

print("socket.py: loading gc")

import gc
gc.collect()

print("socket.py: loading: try_mkdir")

def try_mkdir(directory_path) -> bool:
	import os
	try:
		os.stat(directory_path)
		gc.collect()
		return False
	except Exception as ex:
		gc.collect()
		if "No such file or directory" in str(ex):
			# normal
			os.mkdir(directory_path)
			gc.collect()
			return True
		elif "[Errno 2] ENOENT" in str(ex):
			# micropython
			os.mkdir(directory_path)
			gc.collect()
			return True
		else:
			raise ex


def join_path(*paths):
	_full_path = paths[0]
	for _path in paths:
		if _full_path[-1] != "/":
			_full_path += "/"
		_full_path += _path
	gc.collect()
	return _full_path

print("socket.py: loading socket")

try:
	import usocket as socket
except ImportError:
	gc.collect()

	import socket

import ssl
import certifi

_is_threading_async = True

print("socket.py: loading json")

try:
	import ujson as json
except ImportError:
	gc.collect()

	import json

print("socket.py: loading Encryption")

try:
	import cryptography.fernet
	import base64

	class Encryption():

		def __init__(self, *, key: bytes):

			self.__key = key

			self.__key_base64 = base64.b64encode(self.__key)

		@staticmethod
		def get_random_key():
			_key = cryptography.fernet.Fernet.generate_key()
			return _key

		def encrypt(self, *, decrypted_data: bytes) -> bytes:
			_fernet = cryptography.fernet.Fernet(
				key=self.__key_base64
			)
			_encrypted_message_bytes = _fernet.encrypt(
				data=decrypted_data
			)
			return _encrypted_message_bytes

		def decrypt(self, *, encrypted_data: bytes) -> bytes:
			_fernet = cryptography.fernet.Fernet(
				key=self.__key_base64
			)
			_decrypted_message_bytes = _fernet.decrypt(
				token=encrypted_data
			)
			return _decrypted_message_bytes

except ImportError:
	gc.collect()

	class Encryption():

		def __init__(self):
			pass

		@staticmethod
		def get_random_key():
			raise NotImplementedError()

		def encrypt(self, *, decrypted_data: bytes) -> bytes:
			raise NotImplementedError()

		def decrypt(self, *, encrypted_data: bytes) -> bytes:
			raise NotImplementedError()

print("socket.py: loading get_machine_guid")

try:
	import network
	import hashlib

	def get_machine_guid() -> str:
		_wlan = network.WLAN()
		_mac_bytes = _wlan.config("mac")
		_sha256 = hashlib.sha256()
		_sha256.update(_mac_bytes)
		_hashed_bytes = _sha256.digest()
		_hashed_hex_string = str(_hashed_bytes.hex())
		_guid = _hashed_hex_string[0:8] + "-" + _hashed_hex_string[8:12] + "-" + _hashed_hex_string[12:16] + "-" + _hashed_hex_string[16:20] + "-" + _hashed_hex_string[20:32]
		return _guid
except ImportError:
	gc.collect()

	import uuid

	def get_machine_guid() -> str:
		_node = uuid.getnode()
		_guid = str(uuid.UUID(int=_node, version=4))
		return _guid

print("socket.py: loading time")

import time

print("socket.py: loading get_module_from_file_path")

try:
	import importlib.util

	def get_module_from_file_path(file_path: str, module_name: str):
		_spec = importlib.util.spec_from_file_location(module_name, file_path)
		_module = importlib.util.module_from_spec(_spec)
		_spec.loader.exec_module(_module)
		return _module
except ImportError:
	gc.collect()

	def get_module_from_file_path(file_path: str, module_name: str):
		raise NotImplementedError()


print("socket.py: loading internal")


class ReadWriteSocket():

	def __init__(self, *, socket: socket.socket, read_failed_delay_seconds: float):

		self.__socket = socket
		self.__read_failed_delay_seconds = read_failed_delay_seconds

		self.__readable_socket = None

		self.__initialize()

	def __initialize(self):

		self.__socket.setblocking(True)
		if not hasattr(self.__socket, "readline"):
			self.__readable_socket = self.__socket.makefile("rwb")
		else:
			self.__readable_socket = self.__socket

	def read(self, bytes_length: int) -> bytes:

		_remaining_bytes_length = bytes_length
		_bytes_packets = []
		_read_bytes = None
		while _remaining_bytes_length != 0:
			_read_bytes = self.__readable_socket.read(_remaining_bytes_length)
			if _read_bytes is not None:
				_bytes_packets.append(_read_bytes)
				_remaining_bytes_length -= len(_read_bytes)
			else:
				if self.__read_failed_delay_seconds > 0:
					time.sleep(self.__read_failed_delay_seconds)
		_bytes = b"".join(_bytes_packets)
		return _bytes

	def write(self, data: bytes):

		self.__readable_socket.write(data)
		self.__readable_socket.flush()

	def close(self):

		if self.__readable_socket != self.__socket:
			del self.__readable_socket
		self.__socket.close()


class EncryptedReadWriteSocket():

	def __init__(self, *, read_write_socket: ReadWriteSocket, encryption: Encryption):

		self.__read_write_socket = read_write_socket
		self.__encryption = encryption

		self.__current_buffer = b""

	def read(self, bytes_length: int) -> bytes:

		while len(self.__current_buffer) < bytes_length:
			_encrypted_bytes_length_bytes = self.__read_write_socket.read(8)
			_encrypted_bytes_length = int.from_bytes(_encrypted_bytes_length_bytes, "big")
			_encrypted_bytes = self.__read_write_socket.read(_encrypted_bytes_length)
			_decrypted_bytes = self.__encryption.decrypt(
				encrypted_data=_encrypted_bytes
			)
			self.__current_buffer += _decrypted_bytes
		_buffer = self.__current_buffer[:bytes_length]
		self.__current_buffer = self.__current_buffer[bytes_length:]
		return _buffer

	def write(self, data: bytes):

		_encrypted_bytes = self.__encryption.encrypt(
			decrypted_data=data
		)
		_encrypted_bytes_length = len(_encrypted_bytes)
		_encrypted_bytes_length_bytes = _encrypted_bytes_length.to_bytes(8, "big")
		self.__read_write_socket.write(_encrypted_bytes_length_bytes)
		self.__read_write_socket.write(_encrypted_bytes)

	def close(self):

		self.__read_write_socket.close()


class TextReader():

	def __init__(self, *, text: str):

		self.__text = text

	def get_bytes(self, start_index: int, length: int) -> bytes:
		return self.__text[start_index:start_index + length].encode()

	def get_length(self) -> int:
		return len(self.__text)

	def close(self):
		self.__text = None


class FileReader():

	def __init__(self, *, file_path: str):

		self.__file_path = file_path

		self.__file_handle = None

	def get_bytes(self, start_index: int, length: int) -> bytes:
		if self.__file_handle is None:
			self.__file_handle = open(self.__file_path, "rb")
		self.__file_handle.seek(start_index, 0)
		_bytes = self.__file_handle.read(length)
		return _bytes

	def get_length(self) -> int:
		if self.__file_handle is None:
			self.__file_handle = open(self.__file_path, "rb")
		self.__file_handle.seek(0, 2)
		return self.__file_handle.tell()

	def close(self):
		self.__file_handle.close()
		self.__file_handle = None
		self.__file_path = None


class TextBuilder():

	def __init__(self):

		self.__buffers = []
		self.__current_length = 0

	def write_bytes(self, index: int, data: bytes):
		_length = len(data)
		self.__buffers.append((index, _length, data))
		_buffer_length = index + _length
		if _buffer_length > self.__current_length:
			self.__current_length = _buffer_length

	def close(self) -> str:
		_text_bytes = [0] * self.__current_length
		for _buffer_index, _buffer_length, _buffer_data in self.__buffers:
			_text_bytes[_buffer_index:_buffer_index + _buffer_length] = _buffer_data
		_text = bytes(_text_bytes).decode()
		self.__buffers = None
		self.__current_length = 0
		return _text


class FileBuilder():

	def __init__(self, *, file_path: str):

		self.__file_path = file_path

		self.__file_handle = None

	def write_bytes(self, index: int, data: bytes):
		if self.__file_handle is None:
			self.__file_handle = open(self.__file_path, "wb")
		self.__file_handle.seek(index, 0)
		self.__file_handle.write(data)

	def close(self) -> str:
		if self.__file_handle is not None:
			self.__file_handle.close()
			self.__file_handle = None
		_file_path = self.__file_path
		self.__file_path = None
		return _file_path


class ClientSocketTimeoutException(Exception):

	def __init__(self, *, timeout_thread: TimeoutThread):

		self.__timeout_thread = timeout_thread

	def get_timeout_thread(self) -> TimeoutThread:
		return self.__timeout_thread


class ClientSocket():

	def __init__(self, *, packet_bytes_length: int, read_failed_delay_seconds: float, socket=None, encryption: Encryption = None, delay_between_packets_seconds: float = 0, timeout_seconds: float = None):

		self.__packet_bytes_length = packet_bytes_length
		self.__read_failed_delay_seconds = read_failed_delay_seconds
		self.__encryption = encryption
		self.__delay_between_packets_seconds = delay_between_packets_seconds
		self.__timeout_seconds = timeout_seconds

		self.__ip_address = None  # type: str
		self.__port = None  # type: int
		self.__socket = socket  # type: socket.socket
		self.__read_write_socket = None  # type: ReadWriteSocket
		self.__writing_threads_running_total = 0
		self.__writing_threads_running_total_semaphore = Semaphore()
		self.__reading_threads_running_total = 0
		self.__reading_threads_running_total_semaphore = Semaphore()
		self.__writing_data_queue = []
		self.__writing_data_queue_semaphore = Semaphore()
		self.__is_writing_thread_running = False
		self.__write_started_semaphore = Semaphore()
		self.__reading_callback_queue = []
		self.__reading_callback_queue_semaphore = Semaphore()
		self.__is_reading_thread_running = False
		self.__read_started_semaphore = Semaphore()
		self.__exception = None  # type: Exception
		self.__exception_semaphore = Semaphore()
		self.__writing_semaphore = Semaphore()  # block closing while writing
		self.__reading_semaphore = Semaphore()  # block closing while reading

		self.__initialize()

	def __initialize(self):

		self.__wrap_socket()

	def __wrap_socket(self):

		if self.__socket is not None:
			_read_write_socket = ReadWriteSocket(
				socket=self.__socket,
				read_failed_delay_seconds=self.__read_failed_delay_seconds
			)
			if self.__encryption is not None:
				self.__read_write_socket = EncryptedReadWriteSocket(
					read_write_socket=_read_write_socket,
					encryption=self.__encryption
				)
			else:
				self.__read_write_socket = _read_write_socket

	def connect_to_server(self, *, ip_address: str, port: int, is_ssl: bool):

		if self.__socket is not None:
			raise Exception(f"Cannot connect while already connected.")

		self.__ip_address = ip_address
		self.__port = port

		self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		if is_ssl:
			ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=certifi.where())
			ssl_context.verify_mode = ssl.CERT_REQUIRED
			ssl_context.check_hostname = False
			self.__socket = ssl_context.wrap_socket(self.__socket, server_side=False)
			#self.__socket = ssl.wrap_socket(self.__socket, ssl_version=ssl.PROTOCOL_TLS)

		self.__socket.connect((self.__ip_address, self.__port))

		self.__wrap_socket()

	def is_writing(self) -> bool:
		return self.__writing_threads_running_total > 0

	def is_reading(self) -> bool:
		return self.__reading_threads_running_total > 0

	def __write(self, *, reader: TextReader or FileReader, is_async: bool):

		_blocking_semaphore = None
		self.__writing_data_queue_semaphore.acquire()
		if not is_async:
			_blocking_semaphore = Semaphore()
			_blocking_semaphore.acquire()
		self.__writing_data_queue.append((self.__delay_between_packets_seconds, reader, _blocking_semaphore))
		_is_writing_thread_needed = not self.__is_writing_thread_running
		if _is_writing_thread_needed:
			self.__is_writing_thread_running = True

		self.__exception_semaphore.acquire()
		_exception = self.__exception  # get potentially non-null exception
		self.__exception = None  # clear exception if non-null
		self.__exception_semaphore.release()

		self.__writing_data_queue_semaphore.release()

		if _exception is not None:
			raise _exception

		def _writing_thread_method():
			self.__writing_semaphore.acquire()
			try:
				_is_running = True
				while _is_running:

					def _write_method():
						nonlocal _is_running
						self.__writing_data_queue_semaphore.acquire()
						if len(self.__writing_data_queue) == 0:
							self.__is_writing_thread_running = False
							_is_running = False
							self.__writing_data_queue_semaphore.release()
							self.__writing_threads_running_total_semaphore.acquire()
							self.__writing_threads_running_total -= 1
							self.__writing_threads_running_total_semaphore.release()
						else:
							_exception = None
							_blocking_semaphore = None
							try:
								_delay_between_packets_seconds, _reader, _blocking_semaphore = self.__writing_data_queue.pop(0)
								self.__writing_data_queue_semaphore.release()

								_text_bytes_length = _reader.get_length()
								_packet_bytes_length = self.__packet_bytes_length
								_packets_total = int((_text_bytes_length + _packet_bytes_length - 1) / _packet_bytes_length)
								_packets_total_bytes = _packets_total.to_bytes(8, "big")

								self.__read_write_socket.write(_packets_total_bytes)

								for _packet_index in range(_packets_total):
									_current_packet_bytes_length = min(_text_bytes_length - _packet_bytes_length * _packet_index, _packet_bytes_length)
									_current_packet_bytes_length_bytes = _current_packet_bytes_length.to_bytes(8, "big")  # TODO fix based on possible maximum

									self.__read_write_socket.write(_current_packet_bytes_length_bytes)

									_current_text_bytes_index = _packet_index * _packet_bytes_length
									_packet_bytes = _reader.get_bytes(_current_text_bytes_index, _current_packet_bytes_length)

									self.__read_write_socket.write(_packet_bytes)

									time.sleep(self.__delay_between_packets_seconds)

								_reader.close()

							except Exception as ex:
								# saving the exception until after the _blocking_semaphore can be released
								_exception = ex

							if _blocking_semaphore is not None:
								_blocking_semaphore.release()

							if _exception is not None:
								raise _exception

					if self.__timeout_seconds is None:
						_write_method()
					else:
						_timeout_thread = TimeoutThread(
							target=_write_method,
							timeout_seconds=self.__timeout_seconds
						)
						_timeout_thread.start()
						_is_successful = _timeout_thread.try_wait()
						if not _is_successful:
							raise ClientSocketTimeoutException(
								timeout_thread=_timeout_thread
							)

					time.sleep(0)  # permit other threads to take action

			except Exception as ex:
				self.__exception_semaphore.acquire()
				if self.__exception is None:
					self.__exception = ex
				self.__exception_semaphore.release()
			self.__writing_semaphore.release()

		if _is_writing_thread_needed:
			self.__writing_threads_running_total_semaphore.acquire()
			self.__writing_threads_running_total += 1
			self.__writing_threads_running_total_semaphore.release()
			_writing_thread = start_thread(_writing_thread_method)

		if not is_async:
			# this will block the thread if the _write_method throws an unhandled exception
			_blocking_semaphore.acquire()
			_blocking_semaphore.release()

		self.__exception_semaphore.acquire()
		_exception = self.__exception  # get potentially non-null exception
		self.__exception = None  # clear exception if non-null
		self.__exception_semaphore.release()

		if _exception is not None:
			raise _exception

	def write_async(self, text: str):

		self.__write(
			reader=TextReader(
				text=text
			),
			is_async=True
		)

	def write(self, text: str):

		self.__write(
			reader=TextReader(
				text=text
			),
			is_async=False
		)

	def upload_async(self, file_path: str):

		self.__write(
			reader=FileReader(
				file_path=file_path
			),
			is_async=True
		)

	def upload(self, file_path: str):

		self.__write(
			reader=FileReader(
				file_path=file_path
			),
			is_async=False
		)

	def __read(self, *, callback, builder: TextBuilder or FileBuilder, is_async: bool):

		_blocking_semaphore = None
		self.__reading_callback_queue_semaphore.acquire()
		if not is_async:
			_blocking_semaphore = Semaphore()
			_blocking_semaphore.acquire()
		self.__reading_callback_queue.append((self.__delay_between_packets_seconds, callback, builder, _blocking_semaphore))
		_is_reading_thread_needed = not self.__is_reading_thread_running
		if _is_reading_thread_needed:
			self.__is_reading_thread_running = True

		self.__exception_semaphore.acquire()
		_exception = self.__exception  # get potentially non-null exception
		self.__exception = None  # clear exception if non-null
		self.__exception_semaphore.release()

		self.__reading_callback_queue_semaphore.release()

		if _exception is not None:
			raise _exception

		def _reading_thread_method():
			self.__reading_semaphore.acquire()
			try:
				_is_running = True
				while _is_running:

					def _read_method():
						nonlocal _is_running
						self.__reading_callback_queue_semaphore.acquire()
						if len(self.__reading_callback_queue) == 0:
							self.__is_reading_thread_running = False
							_is_running = False
							self.__reading_callback_queue_semaphore.release()
							self.__reading_threads_running_total_semaphore.acquire()
							self.__reading_threads_running_total -= 1
							self.__reading_threads_running_total_semaphore.release()
						else:
							_exception = None
							_blocking_semaphore = None
							try:
								_delay_between_packets_seconds, _callback, _builder, _blocking_semaphore = self.__reading_callback_queue.pop(0)
								self.__reading_callback_queue_semaphore.release()

								_packets_total_bytes = self.__read_write_socket.read(8)  # TODO only send the number of bytes required to transmit based on self.__packet_bytes_length
								_packets_total = int.from_bytes(_packets_total_bytes, "big")
								_byte_index = 0
								if _packets_total != 0:
									for _packet_index in range(_packets_total):
										_text_bytes_length_string_bytes = self.__read_write_socket.read(8)
										_text_bytes_length = int.from_bytes(_text_bytes_length_string_bytes, "big")
										_text_bytes = self.__read_write_socket.read(_text_bytes_length)
										_builder.write_bytes(_byte_index, _text_bytes)
										_byte_index += len(_text_bytes)

										time.sleep(self.__delay_between_packets_seconds)

								_callback()

							except Exception as ex:
								# saving the exception until after the _blocking_semaphore can be released
								_exception = ex

							if _blocking_semaphore is not None:
								_blocking_semaphore.release()

							if _exception is not None:
								raise _exception

						time.sleep(0)  # permit other threads to take action

					if self.__timeout_seconds is None:
						_read_method()
					else:
						_timeout_thread = TimeoutThread(
							target=_read_method,
							timeout_seconds=self.__timeout_seconds
						)
						_timeout_thread.start()
						_is_successful = _timeout_thread.try_wait()
						if not _is_successful:
							raise ClientSocketTimeoutException(
								timeout_thread=_timeout_thread
							)

			except Exception as ex:
				self.__exception_semaphore.acquire()
				if self.__exception is None:
					self.__exception = ex
				self.__exception_semaphore.release()
				if not is_async:
					_blocking_semaphore.release()
			self.__reading_semaphore.release()

		if _is_reading_thread_needed:
			self.__reading_threads_running_total_semaphore.acquire()
			self.__reading_threads_running_total += 1
			self.__reading_threads_running_total_semaphore.release()
			_reading_thread = start_thread(_reading_thread_method)

		if not is_async:
			# this will block the thread if the _read_method throws an unhandled exception
			_blocking_semaphore.acquire()
			_blocking_semaphore.release()

		self.__exception_semaphore.acquire()
		_exception = self.__exception  # get potentially non-null exception
		self.__exception = None  # clear exception if non-null
		self.__exception_semaphore.release()

		if _exception is not None:
			raise _exception

	def read_async(self, callback):

		_builder = TextBuilder()

		def _builder_callback():
			callback(_builder.close())

		self.__read(
			callback=_builder_callback,
			builder=_builder,
			is_async=True
		)

	def read(self) -> str:

		_builder = TextBuilder()
		_text = None
		_is_callback_successful = False

		def _builder_callback():
			nonlocal _text
			nonlocal _is_callback_successful
			_text = _builder.close()
			_is_callback_successful = True

		self.__read(
			callback=_builder_callback,
			builder=_builder,
			is_async=False
		)

		if not _is_callback_successful:
			raise Exception(f"Read process failed to block sync method before returning.")

		return _text

	def download_async(self, file_path: str, callback):

		_builder = FileBuilder(
			file_path=file_path
		)

		def _builder_callback():
			callback(_builder.close())

		self.__read(
			callback=_builder_callback,
			builder=_builder,
			is_async=True
		)

	def download(self, file_path: str):

		_builder = FileBuilder(
			file_path=file_path
		)

		def _builder_callback():
			_builder.close()

		self.__read(
			callback=_builder_callback,
			builder=_builder,
			is_async=False
		)

	def close(self):

		# ensure that the read and write threads have had a chance to complete
		self.__reading_semaphore.acquire()
		self.__reading_semaphore.release()
		self.__writing_semaphore.acquire()
		self.__writing_semaphore.release()

		_close_exception = None
		try:
			self.__read_write_socket.close()
		except Exception as ex:
			_close_exception = ex

		if self.__exception is not None:
			if isinstance(self.__exception, ClientSocketTimeoutException):
				try:
					self.__exception.get_timeout_thread().try_join()  # this should evaluate immediately if the socket close completed
				except ConnectionResetError as ex:
					pass  # expected outcome from closed socket
			raise self.__exception
		elif _close_exception is not None:
			raise _close_exception


class ClientSocketFactory():

	def __init__(self, *, to_server_packet_bytes_length: int, server_read_failed_delay_seconds: float, encryption: Encryption = None, delay_between_packets_seconds: float = 0):

		self.__to_server_packet_bytes_length = to_server_packet_bytes_length
		self.__server_read_failed_delay_seconds = server_read_failed_delay_seconds
		self.__encryption = encryption
		self.__delay_between_packets_seconds = delay_between_packets_seconds

	def get_client_socket(self) -> ClientSocket:
		return ClientSocket(
			packet_bytes_length=self.__to_server_packet_bytes_length,
			read_failed_delay_seconds=self.__server_read_failed_delay_seconds,
			encryption=self.__encryption,
			delay_between_packets_seconds=self.__delay_between_packets_seconds
		)


class ServerSocket():

	def __init__(self, *, to_client_packet_bytes_length: int, listening_limit_total: int, accept_timeout_seconds: float, client_read_failed_delay_seconds: float, encryption: Encryption = None, delay_between_packets_seconds: float = 0, client_socket_timeout_seconds: float = None):

		self.__to_client_packet_bytes_length = to_client_packet_bytes_length
		self.__listening_limit_total = listening_limit_total
		self.__accept_timeout_seconds = accept_timeout_seconds
		self.__client_read_failed_delay_seconds = client_read_failed_delay_seconds
		self.__encryption = encryption
		self.__delay_between_packets_seconds = delay_between_packets_seconds
		self.__client_socket_timeout_seconds = client_socket_timeout_seconds

		self.__host_ip_address = None  # type: str
		self.__host_port = None  # type: int
		self.__bindable_address = None
		self.__is_accepting = False
		self.__accepting_thread = None  # type: threading.Thread
		self.__accepting_socket = None
		self.__blocked_client_addresses = []

	def start_accepting_clients(self, *, host_ip_address: str, host_port: int, on_accepted_client_method, is_ssl: bool):

		if self.__is_accepting:
			raise Exception("Cannot start accepting clients while already accepting.")
		else:

			self.__is_accepting = True

			self.__host_ip_address = host_ip_address
			self.__host_port = host_port
			self.__bindable_address = socket.getaddrinfo(self.__host_ip_address, self.__host_port, 0, socket.SOCK_STREAM)[0][-1]

			def _process_connection_thread_method(connection_socket, address, to_client_packet_bytes_length, on_accepted_client_method, client_read_failed_delay_seconds: float):
				try:
					if address not in self.__blocked_client_addresses:
						_accepted_socket = ClientSocket(
							packet_bytes_length=to_client_packet_bytes_length,
							read_failed_delay_seconds=client_read_failed_delay_seconds,
							socket=connection_socket,
							encryption=self.__encryption,
							delay_between_packets_seconds=self.__delay_between_packets_seconds,
							timeout_seconds=self.__client_socket_timeout_seconds
						)
						_is_valid_client = on_accepted_client_method(_accepted_socket)
						if _is_valid_client == False:
							self.__blocked_client_addresses.append(address)
				except Exception as ex:
					print(f"ServerSocket: _process_connection_thread_method: {ex}")
				#connection_socket.shutdown(2)
				connection_socket.close()
				#del connection_socket

			def _accepting_thread_method(to_client_packet_bytes_length, on_accepted_client_method, listening_limit_total, accept_timeout_seconds, client_read_failed_delay_seconds):
				nonlocal is_ssl

				self.__accepting_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

				if is_ssl:
					ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=certifi.where())
					ssl_context.verify_mode = ssl.CERT_REQUIRED
					ssl_context.check_hostname = False
					self.__accepting_socket = ssl_context.wrap_socket(self.__accepting_socket, server_side=True)
					#self.__accepting_socket = ssl.wrap_socket(self.__accepting_socket, ssl_version=ssl.PROTOCOL_TLS)

				self.__accepting_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				self.__accepting_socket.bind(self.__bindable_address)
				self.__accepting_socket.listen(listening_limit_total)
				self.__accepting_socket.settimeout(accept_timeout_seconds)
				while self.__is_accepting:
					try:
						_connection_socket, _address = self.__accepting_socket.accept()
						#_connection_socket.setblocking(False)
						_connection_thread = start_thread(_process_connection_thread_method, _connection_socket, _address, to_client_packet_bytes_length, on_accepted_client_method, client_read_failed_delay_seconds)
					except Exception as ex:
						if str(ex) == "[Errno 116] ETIMEDOUT":
							pass
						elif hasattr(socket, "timeout") and isinstance(ex, socket.timeout):
							pass
						else:
							print("ex: " + str(ex))
							self.__is_accepting = False
					if _is_threading_async:
						time.sleep(0.01)

			self.__accepting_thread = start_thread(_accepting_thread_method, self.__to_client_packet_bytes_length, on_accepted_client_method, self.__listening_limit_total, self.__accept_timeout_seconds, self.__client_read_failed_delay_seconds)

	def is_accepting_clients(self) -> bool:
		return self.__is_accepting

	def stop_accepting_clients(self):

		if not self.__is_accepting:
			raise Exception("Cannot stop accepting clients without first starting.")
		else:
			self.__is_accepting = False
			if self.__accepting_thread is not None:
				self.__accepting_thread.join()

	def close(self):

		if self.__is_accepting:
			raise Exception("Cannot close without first stopping accepting clients.")
		else:
			self.__accepting_socket.close()


class ServerSocketFactory():

	def __init__(self, *,
				 to_client_packet_bytes_length: int,
				 listening_limit_total: int,
				 accept_timeout_seconds: float,
				 client_read_failed_delay_seconds: float,
				 encryption: Encryption = None,
				 delay_between_packets_seconds: float = 0,
				 client_socket_timeout_seconds: float = None):

		self.__to_client_packet_bytes_length = to_client_packet_bytes_length
		self.__listening_limit_total = listening_limit_total
		self.__accept_timeout_seconds = accept_timeout_seconds
		self.__client_read_failed_delay_seconds = client_read_failed_delay_seconds
		self.__encryption = encryption
		self.__delay_between_packets_seconds = delay_between_packets_seconds
		self.__client_socket_timeout_seconds = client_socket_timeout_seconds

	def get_server_socket(self) -> ServerSocket:

		return ServerSocket(
			to_client_packet_bytes_length=self.__to_client_packet_bytes_length,
			listening_limit_total=self.__listening_limit_total,
			accept_timeout_seconds=self.__accept_timeout_seconds,
			client_read_failed_delay_seconds=self.__client_read_failed_delay_seconds,
			encryption=self.__encryption,
			delay_between_packets_seconds=self.__delay_between_packets_seconds,
			client_socket_timeout_seconds=self.__client_socket_timeout_seconds
		)
