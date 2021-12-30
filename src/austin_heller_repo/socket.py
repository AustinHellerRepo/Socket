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

print("socket.py: loading collections")

import collections

print("socket.py: loading internal")


class ReadWriteSocketClosedException(Exception):

	def __init__(self, *args):
		super().__init__(*args)

		pass

	def __str__(self):
		return str(type(self))


class ReadWriteSocket():

	def __init__(self, *, socket: socket.socket, is_debug: bool = False):

		self.__socket = socket
		self.__is_debug = is_debug

		self.__readable_socket = None
		self.__is_closing = False

		self.__initialize()

	def __initialize(self):

		self.__socket.setblocking(True)
		self.__socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		if not hasattr(self.__socket, "readline"):
			self.__readable_socket = self.__socket.makefile("rwb")
		else:
			self.__readable_socket = self.__socket

	def read(self, bytes_length: int) -> bytes:

		if self.__is_debug:
			print("ReadWriteSocket: read: start")
		_remaining_bytes_length = bytes_length
		_bytes_packets = []
		_read_bytes = None
		_debug_read_attempts = 0
		try:
			while _remaining_bytes_length != 0 and not self.__is_closing:
				_read_bytes = self.__readable_socket.read(_remaining_bytes_length)
				_read_bytes_length = len(_read_bytes)
				if _read_bytes_length == 0:
					raise ReadWriteSocketClosedException()
				_bytes_packets.append(_read_bytes)
				_remaining_bytes_length -= _read_bytes_length
		except BrokenPipeError as ex:
			raise ReadWriteSocketClosedException()
		except ConnectionResetError as ex:
			raise ReadWriteSocketClosedException()
		_bytes = b"".join(_bytes_packets)

		if self.__is_debug:
			print("ReadWriteSocket: read: end")

		return _bytes

	def write(self, data: bytes):
		if self.__is_debug:
			print("ReadWriteSocket: write: writing message: " + str(data))
		try:
			self.__readable_socket.write(data)
			self.__readable_socket.flush()
		except BrokenPipeError as ex:
			raise ReadWriteSocketClosedException()
		except ConnectionResetError as ex:
			raise ReadWriteSocketClosedException()

	def close(self):
		if self.__is_debug:
			print("ReadWriteSocket: close: start")
		self.__is_closing = True
		try:
			if self.__is_debug:
				print("ReadWriteSocket: close: shutting down socket")
			self.__socket.shutdown(2)
		except Exception as ex:
			if self.__is_debug:
				print("ReadWriteSocket: close: failed to shutdown socket: " + str(ex))
		if self.__is_debug:
			print("ReadWriteSocket: close: closing socket")
		self.__socket.close()
		if self.__readable_socket != self.__socket:
			if self.__is_debug:
				print("ReadWriteSocket: close: deleting readable_socket")
			del self.__readable_socket
		if self.__is_debug:
			print("ReadWriteSocket: close: deleting socket")
		del self.__socket
		if self.__is_debug:
			print("ReadWriteSocket: close: end")


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

	def __init__(self, *, timeout_thread: TimeoutThread, blocking_semaphore: Semaphore):

		self.__timeout_thread = timeout_thread
		self.__blocking_semaphore = blocking_semaphore

	def get_timeout_thread(self) -> TimeoutThread:
		return self.__timeout_thread

	def get_blocking_semaphore(self) -> Semaphore:
		return self.__blocking_semaphore


class ClientSocket():

	def __init__(self, *, packet_bytes_length: int, ssl_private_key_file_path: str = None, ssl_certificate_file_path: str = None, root_ssl_certificate_file_path: str = None, socket=None, encryption: Encryption = None, delay_between_packets_seconds: float = 0, timeout_seconds: float = None, is_debug: bool = False):

		self.__packet_bytes_length = packet_bytes_length
		self.__ssl_private_key_file_path = ssl_private_key_file_path
		self.__ssl_certificate_file_path = ssl_certificate_file_path
		self.__root_ssl_certificate_file_path = root_ssl_certificate_file_path
		self.__encryption = encryption
		self.__delay_between_packets_seconds = delay_between_packets_seconds
		self.__timeout_seconds = timeout_seconds
		self.__is_debug = is_debug

		self.__ip_address = None  # type: str
		self.__port = None  # type: int
		self.__socket = socket  # type: socket.socket
		self.__read_write_socket = None  # type: ReadWriteSocket
		self.__writing_threads_running_total = 0
		self.__writing_threads_running_total_semaphore = Semaphore()
		self.__reading_threads_running_total = 0
		self.__reading_threads_running_total_semaphore = Semaphore()
		self.__writing_data_queue = collections.deque()
		self.__writing_data_queue_semaphore = Semaphore()
		self.__is_writing_thread_running = False
		self.__write_started_semaphore = Semaphore()
		self.__reading_callback_queue = collections.deque()
		self.__reading_callback_queue_semaphore = Semaphore()
		self.__is_reading_thread_running = False
		self.__read_started_semaphore = Semaphore()
		self.__read_exception = None  # type: Exception
		self.__read_exception_semaphore = Semaphore()
		self.__write_exception = None  # type: Exception
		self.__write_exception_semaphore = Semaphore()
		self.__is_reading = False
		self.__is_writing = False
		self.__is_closing = False
		self.__read_waiting_semaphore = Semaphore()
		self.__write_waiting_semaphore = Semaphore()
		self.__writing_thread = None
		self.__reading_thread = None

		self.__initialize()

	def __initialize(self):

		if (all(file_path is not None for file_path in [self.__ssl_private_key_file_path, self.__ssl_certificate_file_path, self.__root_ssl_certificate_file_path])):
			pass  # this ClientSocket will communicate over SSL
		elif (all(file_path is None for file_path in [self.__ssl_private_key_file_path, self.__ssl_certificate_file_path, self.__root_ssl_certificate_file_path])):
			pass  # this ClientSocket will not communicate over SSL
		else:
			raise Exception("Either submit all SSL-related arguments or none of them.")

		self.__wrap_socket()
		self.__read_waiting_semaphore.acquire()
		self.__write_waiting_semaphore.acquire()

	def __wrap_socket(self):

		if self.__socket is not None:
			_read_write_socket = ReadWriteSocket(
				socket=self.__socket,
				is_debug=self.__is_debug
			)
			if self.__encryption is not None:
				self.__read_write_socket = EncryptedReadWriteSocket(
					read_write_socket=_read_write_socket,
					encryption=self.__encryption
				)
			else:
				self.__read_write_socket = _read_write_socket

	def connect_to_server(self, *, ip_address: str, port: int):

		if self.__socket is not None:
			raise Exception(f"Cannot connect while already connected.")

		self.__ip_address = ip_address
		self.__port = port

		self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		if self.__ssl_certificate_file_path is not None and self.__ssl_private_key_file_path is not None and self.__root_ssl_certificate_file_path is not None:
			#ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.__root_ssl_certificate_file_path)
			ssl_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
			ssl_context.load_verify_locations(self.__root_ssl_certificate_file_path)
			ssl_context.load_cert_chain(
				certfile=self.__ssl_certificate_file_path,
				keyfile=self.__ssl_private_key_file_path
			)
			ssl_context.verify_mode = ssl.CERT_REQUIRED
			self.__socket = ssl_context.wrap_socket(self.__socket, server_side=False, server_hostname=ip_address)
			#self.__socket = ssl.wrap_socket(self.__socket, ssl_version=ssl.PROTOCOL_TLS)

		self.__socket.connect((self.__ip_address, self.__port))

		self.__wrap_socket()

	def is_writing(self) -> bool:
		return self.__is_writing

	def is_reading(self) -> bool:
		return self.__is_reading

	def __try_set_read_exception(self, exception: Exception, during=None):
		self.__read_exception_semaphore.acquire()
		try:
			if self.__read_exception is None:
				self.__read_exception = exception
				if during is not None:
					during()
		finally:
			self.__read_exception_semaphore.release()

	def __try_process_read_exception(self, before=None):
		self.__read_exception_semaphore.acquire()
		try:
			_exception = self.__read_exception
			self.__read_exception = None
		finally:
			self.__read_exception_semaphore.release()

		if before is not None:
			before(_exception)

		if _exception is not None:
			# NOTE: I would like to join on the underlying thread, but this stops the main thread from discovering the exception, closing the client socket, and permitting the thread to end
			#if isinstance(_exception, ClientSocketTimeoutException):
			#	_exception.get_timeout_thread().try_join()  # permits underlying exceptions to propagate
			raise _exception

	def __try_set_write_exception(self, exception: Exception, during=None):
		self.__write_exception_semaphore.acquire()
		try:
			if self.__write_exception is None:
				self.__write_exception = exception
				if during is not None:
					during()
		finally:
			self.__write_exception_semaphore.release()

	def __try_process_write_exception(self, before=None):
		self.__write_exception_semaphore.acquire()
		try:
			_exception = self.__write_exception
			self.__write_exception = None
		finally:
			self.__write_exception_semaphore.release()

		if before is not None:
			before(_exception)

		if _exception is not None:
			# NOTE: I would like to join on the underlying thread, but this stops the main thread from discovering the exception, closing the client socket, and permitting the thread to end
			#if isinstance(_exception, ClientSocketTimeoutException):
			#	_exception.get_timeout_thread().try_join()  # permits underlying exceptions to propagate
			raise _exception

	def __write(self, *, reader: TextReader or FileReader, is_async: bool):

		_blocking_semaphore = None
		self.__writing_data_queue_semaphore.acquire()
		if not is_async:
			if self.__is_debug:
				print(f"ClientSocket: __write: setting up blocking semaphore for sync write")
			_blocking_semaphore = Semaphore()
			_blocking_semaphore.acquire()
		is_empty = not bool(self.__writing_data_queue)
		self.__writing_data_queue.append((self.__delay_between_packets_seconds, reader, _blocking_semaphore))
		if is_empty:
			self.__write_waiting_semaphore.release()
		_is_writing_thread_needed = not self.__is_writing_thread_running
		if _is_writing_thread_needed:
			self.__is_writing_thread_running = True

		def before(ex):
			self.__writing_data_queue_semaphore.release()
			if self.__is_debug:
				print(f"__write: checking exception at top: {ex}")

		self.__try_process_write_exception(before)

		def _writing_thread_method():
			try:
				while not self.__is_closing:

					if self.__is_debug:
						print(f"ClientSocket: __write: _writing_thread_method: self.__write_waiting_semaphore.acquire(): start")

					self.__write_waiting_semaphore.acquire()

					if self.__is_debug:
						print(f"ClientSocket: __write: _writing_thread_method: self.__write_waiting_semaphore.acquire(): end")

					if not self.__is_closing:

						_blocking_semaphore = None

						def _write_method():
							nonlocal _blocking_semaphore

							if self.__is_debug:
								print(f"ClientSocket: __write: _write_method: started")

							try:
								if not self.__is_closing:
									self.__is_writing = True
									self.__writing_data_queue_semaphore.acquire()
									_delay_between_packets_seconds, _reader, _blocking_semaphore = self.__writing_data_queue.popleft()
									if self.__writing_data_queue:
										self.__write_waiting_semaphore.release()
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
								if self.__is_debug:
									print(f"ClientSocket: __write: _write_method: 1 ex: " + str(type(ex)))
								self.__try_set_write_exception(
									exception=ex
								)
							finally:
								if not bool(self.__writing_data_queue) or self.__is_closing:
									self.__is_writing = False
								if _blocking_semaphore is not None:
									_blocking_semaphore.release()
									if self.__is_debug:
										print(f"ClientSocket: __write: _write_method: unblocking semaphore in finally")

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
								if self.__is_debug:
									print(f"ClientSocket: __write: timeout occurred")
								raise ClientSocketTimeoutException(
									timeout_thread=_timeout_thread,
									blocking_semaphore=_blocking_semaphore
								)

			except Exception as ex:
				if self.__is_debug:
					print(f"ClientSocket: __write: 2 ex: {ex}")

				def during():
					if self.__is_debug:
						print(f"ClientSocket: __write: _writing_thread_method: setting exception: {ex}")

				self.__try_set_write_exception(
					exception=ex,
					during=during
				)

				if isinstance(ex, ClientSocketTimeoutException):
					if ex.get_blocking_semaphore() is not None:
						ex.get_blocking_semaphore().release()
			finally:
				if self.__is_debug:
					print(f"ClientSocket: __write: finally: started")
				self.__writing_data_queue_semaphore.acquire()
				while self.__writing_data_queue:
					_delay_between_packets_seconds, _reader, _blocking_semaphore = self.__writing_data_queue.popleft()
					if _blocking_semaphore is not None:
						if self.__is_debug:
							print(f"ClientSocket: __write: _writing_thread_method: finally: unblocking")
						_blocking_semaphore.release()
				self.__writing_data_queue_semaphore.release()
				self.__is_writing = False
				if self.__is_debug:
					print(f"ClientSocket: __write: finally: ended")

		if _is_writing_thread_needed:
			if self.__is_debug:
				print(f"ClientSocket: __write: self.__writing_thread created: start")
			self.__writing_threads_running_total_semaphore.acquire()
			self.__writing_threads_running_total += 1
			self.__writing_threads_running_total_semaphore.release()
			self.__writing_thread = start_thread(_writing_thread_method)
			if self.__is_debug:
				print(f"ClientSocket: __write: self.__writing_thread created: end")

		if not is_async:
			# this will block the thread if the _write_method throws an unhandled exception
			_blocking_semaphore.acquire()
			_blocking_semaphore.release()

		def before(ex):
			if self.__is_debug:
				print(f"__write: checking exception at bottom: {ex}")

		self.__try_process_write_exception(before)

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

		#print(f"ClientSocket: __read: started")

		_blocking_semaphore = None
		self.__reading_callback_queue_semaphore.acquire()
		if not is_async:
			_blocking_semaphore = Semaphore()
			_blocking_semaphore.acquire()
		is_empty = not bool(self.__reading_callback_queue)
		self.__reading_callback_queue.append((self.__delay_between_packets_seconds, callback, builder, _blocking_semaphore))
		if is_empty:
			self.__read_waiting_semaphore.release()
		_is_reading_thread_needed = not self.__is_reading_thread_running
		if _is_reading_thread_needed:
			self.__is_reading_thread_running = True

		def before(ex):
			self.__reading_callback_queue_semaphore.release()
			if self.__is_debug:
				print(f"__read: checking exception at top: {ex}")

		self.__try_process_read_exception(before)

		def _reading_thread_method():
			try:
				while not self.__is_closing:

					self.__read_waiting_semaphore.acquire()

					if not self.__is_closing:

						_blocking_semaphore = None

						def _read_method():
							nonlocal _blocking_semaphore

							if self.__is_debug:
								print(f"ClientSocket: __read: _read_method: started")

							try:
								if not self.__is_closing:
									self.__is_reading = True
									try:
										self.__reading_callback_queue_semaphore.acquire()
										_delay_between_packets_seconds, _callback, _builder, _blocking_semaphore = self.__reading_callback_queue.popleft()
										if self.__reading_callback_queue:
											self.__read_waiting_semaphore.release()
									finally:
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
								#print(f"ClientSocket: __read: _read_method: ex: {ex}")
								#import traceback
								#traceback.print_exc()
								if self.__is_debug:
									print(f"ClientSocket: __read: 1 ex: " + str(ex))

								def during():
									if self.__is_debug:
										print(f"ClientSocket: __read: _read_method: setting exception: {ex}")

								self.__try_set_read_exception(ex, during)

							finally:
								if self.__is_debug:
									print(f"ClientSocket: __read: _read_method: finally")
								if not bool(self.__reading_callback_queue) or self.__is_closing:
									self.__is_reading = False
								if _blocking_semaphore is not None:
									_blocking_semaphore.release()

						if self.__timeout_seconds is None:
							if self.__is_debug:
								print(f"ClientSocket: __read: _reading_thread_method: starting _read_method")
							_read_method()
						else:
							if self.__is_debug:
								print(f"ClientSocket: __read: _reading_thread_method: starting _timeout_thread")
							_timeout_thread = TimeoutThread(
								target=_read_method,
								timeout_seconds=self.__timeout_seconds
							)
							_timeout_thread.start()
							_is_successful = _timeout_thread.try_wait()
							if not _is_successful:
								if self.__is_debug:
									print(f"ClientSocket: __read: timeout failed: existing exception: {self.__exception}")
								raise ClientSocketTimeoutException(
									timeout_thread=_timeout_thread,
									blocking_semaphore=_blocking_semaphore
								)

			except Exception as ex:
				if self.__is_debug:
					print(f"ClientSocket: __read: _reading_thread_method: 2 ex: {ex}")

				def during():
					if self.__is_debug:
						print(f"ClientSocket: __read: _reading_thread_method: setting exception: {ex}")

				self.__try_set_read_exception(ex, during)

				if isinstance(ex, ClientSocketTimeoutException):
					if ex.get_blocking_semaphore() is not None:
						ex.get_blocking_semaphore().release()
			finally:
				if self.__is_debug:
					print(f"ClientSocket: __read: finally: started")
				self.__reading_callback_queue_semaphore.acquire()
				while self.__reading_callback_queue:
					_delay_between_packets_seconds, _callback, _builder, _blocking_semaphore = self.__reading_callback_queue.popleft()
					if _blocking_semaphore is not None:
						if self.__is_debug:
							print(f"ClientSocket: __read: _reading_thread_method: finally: unblocking")
						_blocking_semaphore.release()
				self.__reading_callback_queue_semaphore.release()
				self.__is_reading = False
				if self.__is_debug:
					print(f"ClientSocket: __read: finally: ended")

		if _is_reading_thread_needed:
			if self.__is_debug:
				print(f"ClientSocket: __read: self.__reading_thread created: start")
			self.__reading_threads_running_total_semaphore.acquire()
			self.__reading_threads_running_total += 1
			self.__reading_threads_running_total_semaphore.release()
			self.__reading_thread = start_thread(_reading_thread_method)
			if self.__is_debug:
				print(f"ClientSocket: __read: self.__reading_thread created: end")

		if not is_async:
			# this will block the thread if the _read_method throws an unhandled exception
			_blocking_semaphore.acquire()
			_blocking_semaphore.release()

		def before(ex):
			if self.__is_debug:
				print(f"__read: checking exception at bottom: {ex}")

		self.__try_process_read_exception(before)

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

		def _builder_callback():
			nonlocal _text
			_text = _builder.close()

		if self.__is_debug:
			print(f"reading (sync) started")

		self.__read(
			callback=_builder_callback,
			builder=_builder,
			is_async=False
		)

		if self.__is_debug:
			print(f"reading (sync) ended")

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

		if self.__is_debug:
			print(f"ClientSocket: close: start")

		self.__is_closing = True

		_close_exception = None
		try:
			if self.__is_debug:
				print(f"ClientSocket: close: closing read_write_socket")
			self.__read_write_socket.close()
			if self.__is_debug:
				print(f"ClientSocket: close: closed read_write_socket")
		except Exception as ex:
			_close_exception = ex

		if _close_exception is not None:
			raise _close_exception

		try:
			self.__read_waiting_semaphore.release()
		except Exception as ex:
			pass

		try:
			self.__write_waiting_semaphore.release()
		except Exception as ex:
			pass

		if self.__reading_thread is not None:
			if self.__is_debug:
				print(f"ClientSocket: close: reading_thread join: start")
			self.__reading_thread.join()
			if self.__is_debug:
				print(f"ClientSocket: close: reading_thread join: end")
		else:
			if self.__is_debug:
				print(f"ClientSocket: close: reading_thread is None")

		if self.__writing_thread is not None:
			if self.__is_debug:
				print(f"ClientSocket: close: writing_thread join: start")
			self.__writing_thread.join()
			if self.__is_debug:
				print(f"ClientSocket: close: writing_thread join: end")
		else:
			if self.__is_debug:
				print(f"ClientSocket: close: writing_thread is None")

		if self.__is_debug:
			print(f"ClientSocket: close: end")


class ClientSocketFactory():

	def __init__(self, *, to_server_packet_bytes_length: int, ssl_private_key_file_path: str = None, ssl_certificate_file_path: str = None, root_ssl_certificate_file_path: str = None, encryption: Encryption = None, delay_between_packets_seconds: float = 0, is_debug: bool = False):

		self.__to_server_packet_bytes_length = to_server_packet_bytes_length
		self.__ssl_private_key_file_path = ssl_private_key_file_path
		self.__ssl_certificate_file_path = ssl_certificate_file_path
		self.__root_ssl_certificate_file_path = root_ssl_certificate_file_path
		self.__encryption = encryption
		self.__delay_between_packets_seconds = delay_between_packets_seconds
		self.__is_debug = is_debug

	def get_client_socket(self) -> ClientSocket:
		return ClientSocket(
			packet_bytes_length=self.__to_server_packet_bytes_length,
			ssl_private_key_file_path=self.__ssl_private_key_file_path,
			ssl_certificate_file_path=self.__ssl_certificate_file_path,
			root_ssl_certificate_file_path=self.__root_ssl_certificate_file_path,
			encryption=self.__encryption,
			delay_between_packets_seconds=self.__delay_between_packets_seconds,
			is_debug=self.__is_debug
		)


class ServerSocket():

	def __init__(self, *, to_client_packet_bytes_length: int, listening_limit_total: int, accept_timeout_seconds: float, ssl_private_key_file_path: str = None, ssl_certificate_file_path: str = None, root_ssl_certificate_file_path: str = None, encryption: Encryption = None, delay_between_packets_seconds: float = 0, client_socket_timeout_seconds: float = None, is_debug: bool = False):

		self.__to_client_packet_bytes_length = to_client_packet_bytes_length
		self.__listening_limit_total = listening_limit_total
		self.__accept_timeout_seconds = accept_timeout_seconds
		self.__ssl_private_key_file_path = ssl_private_key_file_path
		self.__ssl_certificate_file_path = ssl_certificate_file_path
		self.__root_ssl_certificate_file_path = root_ssl_certificate_file_path
		self.__encryption = encryption
		self.__delay_between_packets_seconds = delay_between_packets_seconds
		self.__client_socket_timeout_seconds = client_socket_timeout_seconds
		self.__is_debug = is_debug

		self.__host_ip_address = None  # type: str
		self.__host_port = None  # type: int
		self.__bindable_address = None
		self.__is_accepting = False
		self.__accepting_thread = None  # type: threading.Thread
		self.__accepting_socket = None
		self.__blocked_client_addresses = []
		self.__connected_threads = []

		self.__initialize()

	def __initialize(self):

		if (all(file_path is not None for file_path in [self.__ssl_private_key_file_path, self.__ssl_certificate_file_path, self.__root_ssl_certificate_file_path])):
			pass  # this ClientSocket will communicate over SSL
		elif (all(file_path is None for file_path in [self.__ssl_private_key_file_path, self.__ssl_certificate_file_path, self.__root_ssl_certificate_file_path])):
			pass  # this ClientSocket will not communicate over SSL
		else:
			raise Exception("Either submit all SSL-related arguments or none of them.")

	def start_accepting_clients(self, *, host_ip_address: str, host_port: int, on_accepted_client_method):

		if self.__is_accepting:
			raise Exception("Cannot start accepting clients while already accepting.")
		else:

			self.__is_accepting = True

			self.__host_ip_address = host_ip_address
			self.__host_port = host_port
			self.__bindable_address = socket.getaddrinfo(self.__host_ip_address, self.__host_port, 0, socket.SOCK_STREAM)[0][-1]

			def _process_connection_thread_method(connection_socket, address, to_client_packet_bytes_length, on_accepted_client_method):
				accepted_client_socket = None
				try:
					if address not in self.__blocked_client_addresses:
						accepted_client_socket = ClientSocket(
							packet_bytes_length=to_client_packet_bytes_length,
							ssl_private_key_file_path=self.__ssl_private_key_file_path,
							ssl_certificate_file_path=self.__ssl_certificate_file_path,
							root_ssl_certificate_file_path=self.__root_ssl_certificate_file_path,
							socket=connection_socket,
							encryption=self.__encryption,
							delay_between_packets_seconds=self.__delay_between_packets_seconds,
							timeout_seconds=self.__client_socket_timeout_seconds,
							is_debug=self.__is_debug
						)
						_is_valid_client = on_accepted_client_method(accepted_client_socket)
						if _is_valid_client == False:
							self.__blocked_client_addresses.append(address)
					else:
						# blocked connection
						connection_socket.shutdown(2)
						connection_socket.close()
				except Exception as ex:
					if self.__is_debug:
						print(f"ServerSocket: _process_connection_thread_method: ex: {ex}")
					# NOTE: shutting down causes other issues for clients
					#connection_socket.shutdown(2)
					try:
						#connection_socket.close()
						if accepted_client_socket is not None:
							# this will properly close read/write threads internal to the client socket
							accepted_client_socket.close()
					except Exception as ex_close:
						if self.__is_debug:
							print(f"ServerSocket: _process_connection_thread_method: ex_close: {ex_close}")
				finally:
					# NOTE: the process method may be async, so I think that the state of the client must be determined by the user via the on_accepted_client_method callback
					# connection_socket.shutdown(2)
					# connection_socket.close()
					pass

			def _accepting_thread_method(to_client_packet_bytes_length, on_accepted_client_method, listening_limit_total, accept_timeout_seconds):

				self.__accepting_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				# TODO consider setting the IPPROTO just like the client socket

				if self.__ssl_private_key_file_path is not None and self.__ssl_certificate_file_path is not None and self.__root_ssl_certificate_file_path is not None:
					#ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=self.__root_ssl_certificate_file_path)
					ssl_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
					ssl_context.load_verify_locations(self.__root_ssl_certificate_file_path)
					ssl_context.load_cert_chain(
						certfile=self.__ssl_certificate_file_path,
						keyfile=self.__ssl_private_key_file_path
					)
					ssl_context.verify_mode = ssl.CERT_REQUIRED
					# NOTE this should not accept server_hostname since it is server-side
					self.__accepting_socket = ssl_context.wrap_socket(self.__accepting_socket, server_side=True)
					#self.__accepting_socket = ssl.wrap_socket(self.__accepting_socket, ssl_version=ssl.PROTOCOL_TLS)

				self.__accepting_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				self.__accepting_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
				self.__accepting_socket.bind(self.__bindable_address)
				self.__accepting_socket.listen(listening_limit_total)
				self.__accepting_socket.settimeout(accept_timeout_seconds)

				while self.__is_accepting:
					if self.__is_debug:
						print("ServerSocket: start_accepting_clients: loop started")
					try:
						_connection_socket, _address = self.__accepting_socket.accept()
						#_connection_socket.setblocking(False)
						connected_thread = start_thread(_process_connection_thread_method, _connection_socket, _address, to_client_packet_bytes_length, on_accepted_client_method)
						self.__connected_threads.append(connected_thread)
					except Exception as ex:
						if self.__is_debug:
							print("ServerSocket: start_accepting_clients: ex: " + str(ex))
						if str(ex) == "[Errno 116] ETIMEDOUT":
							pass
						elif hasattr(socket, "timeout") and isinstance(ex, socket.timeout):
							pass
						else:
							#print("ex: " + str(ex))
							self.__is_accepting = False
					if _is_threading_async:
						time.sleep(0.01)

			self.__accepting_thread = start_thread(_accepting_thread_method, self.__to_client_packet_bytes_length, on_accepted_client_method, self.__listening_limit_total, self.__accept_timeout_seconds)

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
			self.__accepting_socket.shutdown(2)
			self.__accepting_socket.close()

	def join(self):

		if self.__is_accepting:
			raise Exception("Should not join on connected threads while accepting new connections.")
		if self.__is_debug:
			print("ServerSocket: start_accepting_clients: join on connection threads: start")
		for connected_thread in self.__connected_threads:
			connected_thread.join()
		if self.__is_debug:
			print("ServerSocket: start_accepting_clients: join on connection threads: end")


class ServerSocketFactory():

	def __init__(self, *,
				 to_client_packet_bytes_length: int,
				 listening_limit_total: int,
				 accept_timeout_seconds: float,
				 ssl_private_key_file_path: str = None,
				 ssl_certificate_file_path: str = None,
				 root_ssl_certificate_file_path: str = None,
				 encryption: Encryption = None,
				 delay_between_packets_seconds: float = 0,
				 client_socket_timeout_seconds: float = None,
				 is_debug: bool = False):

		self.__to_client_packet_bytes_length = to_client_packet_bytes_length
		self.__listening_limit_total = listening_limit_total
		self.__accept_timeout_seconds = accept_timeout_seconds
		self.__ssl_private_key_file_path = ssl_private_key_file_path
		self.__ssl_certificate_file_path = ssl_certificate_file_path
		self.__root_ssl_certificate_file_path = root_ssl_certificate_file_path
		self.__encryption = encryption
		self.__delay_between_packets_seconds = delay_between_packets_seconds
		self.__client_socket_timeout_seconds = client_socket_timeout_seconds
		self.__is_debug = is_debug

	def get_server_socket(self) -> ServerSocket:

		return ServerSocket(
			to_client_packet_bytes_length=self.__to_client_packet_bytes_length,
			listening_limit_total=self.__listening_limit_total,
			accept_timeout_seconds=self.__accept_timeout_seconds,
			ssl_private_key_file_path=self.__ssl_private_key_file_path,
			ssl_certificate_file_path=self.__ssl_certificate_file_path,
			root_ssl_certificate_file_path=self.__root_ssl_certificate_file_path,
			encryption=self.__encryption,
			delay_between_packets_seconds=self.__delay_between_packets_seconds,
			client_socket_timeout_seconds=self.__client_socket_timeout_seconds,
			is_debug=self.__is_debug
		)
