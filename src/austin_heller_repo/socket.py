
try:
	import usocket as socket
except ImportError:
	import socket

_is_threading_async = True

try:
	import threading

	def start_thread(target, *args, **kwargs):
		_thread = threading.Thread(target=target, args=args, kwargs=kwargs)
		_thread.start()
		return _thread

	class Semaphore():

		def __init__(self):
			self.__lock = threading.Semaphore()

		def acquire(self):
			self.__lock.acquire()

		def release(self):
			self.__lock.release()

except ImportError:
	try:
		import _thread as threading

		def start_thread(target, *args, **kwargs):
			def _thread_method():
				target(*args, **kwargs)
			_thread = threading.start_new_thread(_thread_method, ())
			return _thread

		class Semaphore():

			def __init__(self):
				self.__lock = threading.allocate_lock()

			def acquire(self):
				self.__lock.acquire()

			def release(self):
				self.__lock.release()

	except ImportError:
		def start_thread(target, *args, **kwargs):
			target(*args, **kwargs)
			return None
		_is_threading_async = False

		class Semaphore():

			def __init__(self):
				self.__locks_total = 0

			def acquire(self):
				self.__locks_total += 1
				while self.__locks_total > 1:
					time.sleep(0.1)

			def release(self):
				self.__locks_total -= 1
				if self.__locks_total < 0:
					raise Exception("Unexpected number of releases.")

try:
	import ujson as json
except ImportError:
	import json

import hashlib

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
			#print(f"key: \"{self.__key}\".")
			#print(f"len(key): {len(self.__key)}")
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

try:
	import network

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
	import uuid

	def get_machine_guid() -> str:
		_node = uuid.getnode()
		_guid = str(uuid.UUID(int=_node, version=4))
		return _guid

import time
import re
import os


try:
	import importlib

	def get_module_from_file_path(file_path: str):
		return importlib.import_module(file_path)
except ImportError:

	def get_module_from_file_path(file_path: str):
		raise NotImplementedError()


class BooleanReference():

	def __init__(self, value: bool):
		self.__value = value

	def get(self) -> bool:
		return self.__value

	def set(self, value: bool):
		self.__value = value


class StringReference():

	def __init__(self, value: str):
		self.__value = value

	def get(self) -> str:
		return self.__value

	def set(self, value: str):
		self.__value = value


class ThreadDelay():

	def __init__(self):

		self.__abort_semaphore = Semaphore()
		self.__is_sleeping = False
		self.__is_sleeping_semaphore = Semaphore()
		self.__is_aborted = None  # type: BooleanReference
		self.__is_completed = None  # type: BooleanReference
		self.__sleep_block_semaphore = Semaphore()

	def try_sleep(self, *, seconds: float) -> bool:

		self.__is_sleeping_semaphore.acquire()
		_is_already_sleeping = None
		if not self.__is_sleeping:
			self.__is_sleeping = True
			self.__is_aborted = BooleanReference(False)
			self.__is_completed = BooleanReference(False)
			_is_already_sleeping = False
		else:
			_is_already_sleeping = True
		self.__is_sleeping_semaphore.release()

		if _is_already_sleeping:
			raise Exception("ThreadDelay instance already used for sleeping.")
		else:

			_is_completed_normally = False
			_is_aborted = self.__is_aborted  # type: BooleanReference
			_is_completed = self.__is_completed  # type: BooleanReference

			def _sleep_thread_method():
				nonlocal _is_completed_normally
				nonlocal seconds
				nonlocal _is_aborted
				nonlocal _is_completed
				time.sleep(seconds)
				self.__abort_semaphore.acquire()
				if not _is_aborted.get() and not _is_completed.get():
					_is_completed_normally = True
					_is_completed.set(True)
					self.__is_sleeping = False
					self.__sleep_block_semaphore.release()
				self.__abort_semaphore.release()

			self.__sleep_block_semaphore.acquire()
			_sleep_thread = start_thread(_sleep_thread_method)

			self.__sleep_block_semaphore.acquire()
			self.__sleep_block_semaphore.release()

			return _is_completed_normally

	def try_abort(self) -> bool:

		self.__abort_semaphore.acquire()
		_is_aborted = False
		if self.__is_sleeping:
			if not self.__is_aborted.get() and not self.__is_completed.get():
				self.__is_aborted.set(True)
				self.__is_sleeping = False
				_is_aborted = True
				self.__sleep_block_semaphore.release()
		self.__abort_semaphore.release()

		return _is_aborted


class EncapsulatedThread():

	def __init__(self, *, target, is_running_boolean_reference: BooleanReference, polling_thread_delay: ThreadDelay, error_string_reference: StringReference):

		self.__target = target
		self.__is_running_boolean_reference = is_running_boolean_reference
		self.__polling_thread_delay = polling_thread_delay
		self.__error_string_reference = error_string_reference

		self.__thread = None

	def start(self):

		if self.__thread is not None:
			raise Exception("Must first stop before starting.")

		self.__thread = start_thread(self.__target)

	def stop(self):

		self.__is_running_boolean_reference.set(False)
		self.__polling_thread_delay.try_abort()
		self.__thread.join()
		self.__thread = None

	def get_last_error(self) -> str:
		return self.__error_string_reference.get()


class SemaphoreRequest():

	def __init__(self, *, acquire_semaphore_names, release_semaphore_names):

		self.__acquire_semaphore_names = acquire_semaphore_names
		self.__release_semaphore_names = release_semaphore_names

	def get_aquire_semaphore_names(self):
		return self.__acquire_semaphore_names

	def get_release_semaphore_names(self):
		return self.__release_semaphore_names


class SemaphoreRequestQueue():

	def __init__(self, *, acquired_semaphore_names):

		self.__acquired_semaphore_names = acquired_semaphore_names

		self.__enqueue_semaphore = Semaphore()
		self.__active_queue = []  # this queue is holding semaphore requests that have not yet been attempted
		self.__pending_queue = []  # this queue is holding semaphore requests that were already tried and could not be completed yet
		self.__queue_semaphore = Semaphore()
		self.__dequeue_semaphore = Semaphore()

	def enqueue(self, *, semaphore_request: SemaphoreRequest):

		self.__enqueue_semaphore.acquire()

		_blocking_semaphore = Semaphore()
		_blocking_semaphore.acquire()

		self.__queue_semaphore.acquire()
		self.__active_queue.append((semaphore_request, _blocking_semaphore))
		if len(self.__active_queue) == 1:
			_dequeue_thread = start_thread(self.__dequeue_thread_method)
		self.__queue_semaphore.release()

		self.__enqueue_semaphore.release()

		_blocking_semaphore.acquire()
		_blocking_semaphore.release()

	def __dequeue_thread_method(self):

		def _try_process_semaphore_request(*, semaphore_request: SemaphoreRequest) -> bool:
			# can this semaphore request acquire the necessary semaphores?
			_is_at_least_one_acquired_semaphore = False
			_is_at_least_one_released_semaphore = False
			for _acquire_semaphore_name in _semaphore_request.get_aquire_semaphore_names():
				if _acquire_semaphore_name in self.__acquired_semaphore_names:
					# this acquire semaphore name is already acquired, so it cannot be acquired again
					_is_at_least_one_acquired_semaphore = True
					break
			if not _is_at_least_one_acquired_semaphore:
				# can this semaphore request release the necessary semaphores?
				for _release_semaphore_name in _semaphore_request.get_release_semaphore_names():
					if _release_semaphore_name not in self.__acquired_semaphore_names:
						# this release semaphore name is not currently acquired, so it cannot be released
						_is_at_least_one_released_semaphore = True
						break

			if not _is_at_least_one_acquired_semaphore and not _is_at_least_one_released_semaphore:
				self.__acquired_semaphore_names.extend(_semaphore_request.get_aquire_semaphore_names())
				for _release_semaphore_name in _semaphore_request.get_release_semaphore_names():
					self.__acquired_semaphore_names.remove(_release_semaphore_name)
				return True
			return False

		self.__dequeue_semaphore.acquire()

		_is_queue_empty = False
		while not _is_queue_empty:

			# try to process first pending semaphore request

			self.__queue_semaphore.acquire()
			_semaphore_request, _blocking_semaphore = self.__active_queue.pop(0)
			_is_queue_empty = (len(self.__active_queue) == 0)
			self.__queue_semaphore.release()

			_is_active_semaphore_request_processed = _try_process_semaphore_request(
				semaphore_request=_semaphore_request
			)

			# if it could be processed, then release blocking semaphore and run through the pending semaphore requests
			if _is_active_semaphore_request_processed:
				_blocking_semaphore.release()
				#time.sleep(0.01)

				_processed_pending_queue_indexes = []

				for _pending_queue_index, (_semaphore_request, _blocking_semaphore) in enumerate(self.__pending_queue):
					_is_pending_semaphore_request_processed = _try_process_semaphore_request(
						semaphore_request=_semaphore_request
					)
					if _is_pending_semaphore_request_processed:
						_blocking_semaphore.release()
						#time.sleep(0)
						_processed_pending_queue_indexes.append(_pending_queue_index)

				for _pending_queue_index in reversed(_processed_pending_queue_indexes):
					del self.__pending_queue[_pending_queue_index]

			else:
				self.__pending_queue.append((_semaphore_request, _blocking_semaphore))

		self.__dequeue_semaphore.release()


class PreparedSemaphoreRequest():

	def __init__(self, *, semaphore_request: SemaphoreRequest, semaphore_request_queue: SemaphoreRequestQueue):

		self.__semaphore_request = semaphore_request
		self.__semaphore_request_queue = semaphore_request_queue

	def apply(self):

		self.__semaphore_request_queue.enqueue(
			semaphore_request=self.__semaphore_request
		)


class CyclingUnitOfWork():
	'''
	This class represents a unit of work that can be repeated until it determines that there is no more work to perform.
	'''

	def perform(self, *, try_get_next_work_queue_element_prepared_semaphore_request: PreparedSemaphoreRequest, acknowledge_nonempty_work_queue_prepared_semaphore_request: PreparedSemaphoreRequest) -> bool:
		'''
		This function should call try_get_next_work_queue_element_prepared_semaphore_request prior to determining if there is any work to perform and
			then acknowledge_nonempty_work_queue_prepared_semaphore_request only if it determines that it should perform work.
		This function expects that there is an underlying queue of work details that is being appended to asynchronously. In order to ensure that work
			is addressed as quickly as possible as well as accurately, it is expected that the PreparedSemaphoreRequest instances will be used to facilitate
			with the acquiring/releasing of semaphores that orchestrate the state of cycling in the ThreadCycle.
		:param try_get_next_work_queue_element_prepared_semaphore_request: a PreparedSemaphoreRequest that blocks the ThreadCycle from trying to start another
			cycle if it's already running or informing the user that the ThreadCycle is already cycling.
		:param acknowledge_nonempty_work_queue_prepared_semaphore_request: a PreparedSemaphoreRequest that unblocks the ThreadCycle from permitting the user to
			call try_cycle.
		:return: if it completed a unit of work, signifying that another cycle attempt should be made.
		'''
		raise NotImplementedError()


class ThreadCycle():
	'''
	This class will wait for a call to try_cycle and will then continue to perform the cycling_unit_of_work until it returns False, signifying that there is no more work to perform.
	'''

	def __init__(self, *, cycling_unit_of_work: CyclingUnitOfWork):

		self.__cycling_unit_of_work = cycling_unit_of_work

		self.__cycle_thread = None
		self.__is_cycle_thread_running = False
		self.__cycle_thread_semaphore = Semaphore()
		self.__cycle_semaphore_request_queue = SemaphoreRequestQueue(
			acquired_semaphore_names=["blocking cycle"]
		)
		self.__block_cycle_prepared_semaphore_request = PreparedSemaphoreRequest(
			semaphore_request=SemaphoreRequest(
				acquire_semaphore_names=["blocking cycle"],
				release_semaphore_names=[]
			),
			semaphore_request_queue=self.__cycle_semaphore_request_queue
		)
		self.__starting_try_cycle_prepared_semaphore_request = PreparedSemaphoreRequest(
			semaphore_request=SemaphoreRequest(
				acquire_semaphore_names=["try cycle"],
				release_semaphore_names=[]
			),
			semaphore_request_queue=self.__cycle_semaphore_request_queue
		)
		self.__finished_try_cycle_prepared_semaphore_request = PreparedSemaphoreRequest(
			semaphore_request=SemaphoreRequest(
				acquire_semaphore_names=[],
				release_semaphore_names=["try cycle"]
			),
			semaphore_request_queue=self.__cycle_semaphore_request_queue
		)
		self.__finished_try_cycle_and_unblock_prepared_semaphore_request = PreparedSemaphoreRequest(
			semaphore_request=SemaphoreRequest(
				acquire_semaphore_names=[],
				release_semaphore_names=["try cycle", "blocking cycle"]
			),
			semaphore_request_queue=self.__cycle_semaphore_request_queue
		)
		self.__try_get_next_work_queue_element_prepared_semaphore_request = PreparedSemaphoreRequest(
			semaphore_request=SemaphoreRequest(
				acquire_semaphore_names=["try cycle"],
				release_semaphore_names=[]
			),
			semaphore_request_queue=self.__cycle_semaphore_request_queue
		)
		self.__acknowledge_nonempty_work_queue_prepared_semaphore_request = PreparedSemaphoreRequest(
			semaphore_request=SemaphoreRequest(
				acquire_semaphore_names=[],
				release_semaphore_names=["try cycle"]
			),
			semaphore_request_queue=self.__cycle_semaphore_request_queue
		)
		self.__acknowledge_empty_work_queue_prepared_semaphore_request = PreparedSemaphoreRequest(
			semaphore_request=SemaphoreRequest(
				acquire_semaphore_names=[],
				release_semaphore_names=["try cycle"]
			),
			semaphore_request_queue=self.__cycle_semaphore_request_queue
		)
		self.__is_cycling = False

	def start(self):

		self.__cycle_thread_semaphore.acquire()
		if self.__is_cycle_thread_running:
			_error = "Cycle must be stopped before it is started again."
		else:
			self.__is_cycle_thread_running = True
			self.__cycle_thread = start_thread(self.__cycle_thread_method)
			_error = None
		self.__cycle_thread_semaphore.release()

		if _error is not None:
			raise Exception(_error)

	def stop(self):

		self.__cycle_thread_semaphore.acquire()
		if not self.__is_cycle_thread_running:
			_error = "Cycle must be started before it can be stopped."
		else:
			self.__is_cycle_thread_running = False
			self.try_cycle()
			self.__cycle_thread.join()
			self.__cycle_thread = None
			_error = None
		self.__cycle_thread_semaphore.release()

		if _error is not None:
			raise Exception(_error)

	def try_cycle(self) -> bool:
		# try to start the internal cycle
		# if it is already cycling, return false

		self.__starting_try_cycle_prepared_semaphore_request.apply()
		_is_cycling_started = not self.__is_cycling
		if _is_cycling_started:
			self.__is_cycling = True
			self.__finished_try_cycle_and_unblock_prepared_semaphore_request.apply()
		else:
			self.__finished_try_cycle_prepared_semaphore_request.apply()
		return _is_cycling_started

	def __cycle_thread_method(self):
		while self.__is_cycle_thread_running:
			self.__block_cycle_prepared_semaphore_request.apply()
			_is_work_successful = True
			_is_work_started = False
			while _is_work_successful and self.__is_cycle_thread_running:
				_is_work_started = True
				_is_work_successful = self.__cycling_unit_of_work.perform(
					try_get_next_work_queue_element_prepared_semaphore_request=self.__try_get_next_work_queue_element_prepared_semaphore_request,
					acknowledge_nonempty_work_queue_prepared_semaphore_request=self.__acknowledge_nonempty_work_queue_prepared_semaphore_request
				)
			self.__is_cycling = False
			if _is_work_started:
				self.__acknowledge_empty_work_queue_prepared_semaphore_request.apply()


class ReadWriteSocket():

	def __init__(self, *, socket: socket.socket, read_failed_delay_seconds: float):

		self.__socket = socket
		self.__read_failed_delay_seconds = read_failed_delay_seconds

		self.__readable_socket = None

		self.__initialize()

	def __initialize(self):

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
			self.__readable_socket.close()
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

		#print(f"writing \"{data}\"")
		_encrypted_bytes = self.__encryption.encrypt(
			decrypted_data=data
		)
		_encrypted_bytes_length = len(_encrypted_bytes)
		_encrypted_bytes_length_bytes = _encrypted_bytes_length.to_bytes(8, "big")
		self.__read_write_socket.write(_encrypted_bytes_length_bytes)
		self.__read_write_socket.write(_encrypted_bytes)

	def close(self):

		self.__read_write_socket.close()


class ClientSocket():

	def __init__(self, *, packet_bytes_length: int, read_failed_delay_seconds: float, socket=None, encryption: Encryption = None):

		self.__packet_bytes_length = packet_bytes_length
		self.__read_failed_delay_seconds = read_failed_delay_seconds
		self.__encryption = encryption

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

	def connect_to_server(self, *, ip_address: str, port: int):

		if self.__socket is not None:
			raise Exception(f"Cannot connect while already connected.")

		self.__ip_address = ip_address
		self.__port = port

		self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__socket.connect((self.__ip_address, self.__port))

		self.__wrap_socket()

	def is_writing(self) -> bool:
		return self.__writing_threads_running_total > 0

	def is_reading(self) -> bool:
		return self.__reading_threads_running_total > 0

	def __write(self, *, delay_between_packets_seconds: float, text, is_async: bool):

		_blocking_semaphore = None
		self.__writing_data_queue_semaphore.acquire()
		if not is_async:
			_blocking_semaphore = Semaphore()
			_blocking_semaphore.acquire()
		self.__writing_data_queue.append((delay_between_packets_seconds, text, _blocking_semaphore))
		_is_writing_thread_needed = not self.__is_writing_thread_running
		if _is_writing_thread_needed:
			self.__is_writing_thread_running = True
		self.__writing_data_queue_semaphore.release()

		def _writing_thread_method():

			_is_running = True
			while _is_running:

				self.__writing_data_queue_semaphore.acquire()
				if len(self.__writing_data_queue) == 0:
					self.__is_writing_thread_running = False
					_is_running = False
					self.__writing_data_queue_semaphore.release()
					self.__writing_threads_running_total_semaphore.acquire()
					self.__writing_threads_running_total -= 1
					self.__writing_threads_running_total_semaphore.release()
				else:
					_delay_between_packets_seconds, _text, _blocking_semaphore = self.__writing_data_queue.pop(0)
					self.__writing_data_queue_semaphore.release()

					_text_bytes = _text.encode()
					_text_bytes_length = len(_text_bytes)
					_packet_bytes_length = self.__packet_bytes_length
					_packets_total = int((_text_bytes_length + _packet_bytes_length - 1) / _packet_bytes_length)
					_packets_total_bytes = _packets_total.to_bytes(8, "big")

					self.__read_write_socket.write(_packets_total_bytes)

					for _packet_index in range(_packets_total):
						_current_packet_bytes_length = min(_text_bytes_length - _packet_bytes_length * _packet_index, _packet_bytes_length)
						_current_packet_bytes_length_bytes = _current_packet_bytes_length.to_bytes(8, "big")  # TODO fix based on possible maximum

						self.__read_write_socket.write(_current_packet_bytes_length_bytes)

						_current_text_bytes_index = _packet_index * _packet_bytes_length
						_packet_bytes = _text_bytes[_current_text_bytes_index:_current_text_bytes_index + _current_packet_bytes_length]

						self.__read_write_socket.write(_packet_bytes)

						if delay_between_packets_seconds > 0:
							time.sleep(delay_between_packets_seconds)

					if _blocking_semaphore is not None:
						_blocking_semaphore.release()

				time.sleep(0)  # permit other threads to take action

		if _is_writing_thread_needed:
			self.__writing_threads_running_total_semaphore.acquire()
			self.__writing_threads_running_total += 1
			self.__writing_threads_running_total_semaphore.release()
			_writing_thread = start_thread(_writing_thread_method)

		if not is_async:
			_blocking_semaphore.acquire()
			_blocking_semaphore.release()

	def write_async(self, text, delay_between_packets_seconds: float = 0):

		self.__write(
			delay_between_packets_seconds=delay_between_packets_seconds,
			text=text,
			is_async=True
		)

	def write(self, text: str, delay_between_packets_seconds: float = 0):

		self.__write(
			delay_between_packets_seconds=delay_between_packets_seconds,
			text=text,
			is_async=False
		)

	def __read(self, *, delay_between_packets_seconds: float, callback, is_async: bool):

		_blocking_semaphore = None
		self.__reading_callback_queue_semaphore.acquire()
		if not is_async:
			_blocking_semaphore = Semaphore()
			_blocking_semaphore.acquire()
		self.__reading_callback_queue.append((delay_between_packets_seconds, callback, _blocking_semaphore))
		_is_reading_thread_needed = not self.__is_reading_thread_running
		if _is_reading_thread_needed:
			self.__is_reading_thread_running = True
		self.__reading_callback_queue_semaphore.release()

		def _reading_thread_method():

			_is_running = True
			while _is_running:

				self.__reading_callback_queue_semaphore.acquire()
				if len(self.__reading_callback_queue) == 0:
					self.__is_reading_thread_running = False
					_is_running = False
					self.__reading_callback_queue_semaphore.release()
					self.__reading_threads_running_total_semaphore.acquire()
					self.__reading_threads_running_total -= 1
					self.__reading_threads_running_total_semaphore.release()
				else:
					_delay_between_packets_seconds, _callback, _blocking_semaphore = self.__reading_callback_queue.pop(0)
					self.__reading_callback_queue_semaphore.release()

					_packets_total_bytes = self.__read_write_socket.read(8)  # TODO only send the number of bytes required to transmit based on self.__packet_bytes_length
					_packets_total = int.from_bytes(_packets_total_bytes, "big")
					_packets = []
					if _packets_total != 0:
						for _packet_index in range(_packets_total):
							_text_bytes_length_string_bytes = self.__read_write_socket.read(8)
							_text_bytes_length = int.from_bytes(_text_bytes_length_string_bytes, "big")
							_text_bytes = self.__read_write_socket.read(_text_bytes_length)
							_packets.append(_text_bytes)

							if delay_between_packets_seconds > 0:
								time.sleep(delay_between_packets_seconds)

					_text_bytes = b"".join(_packets)
					_text = _text_bytes.decode()

					_callback(_text)

					if _blocking_semaphore is not None:
						_blocking_semaphore.release()

				time.sleep(0)  # permit other threads to take action

		if _is_reading_thread_needed:
			self.__reading_threads_running_total_semaphore.acquire()
			self.__reading_threads_running_total += 1
			self.__reading_threads_running_total_semaphore.release()
			_reading_thread = start_thread(_reading_thread_method)

		if not is_async:
			_blocking_semaphore.acquire()
			_blocking_semaphore.release()

	def read_async(self, callback, delay_between_packets_seconds: float = 0):

		self.__read(
			delay_between_packets_seconds=delay_between_packets_seconds,
			callback=callback,
			is_async=True
		)

	def read(self, delay_between_packets_seconds: float = 0) -> str:

		_text = None
		_is_callback_successful = False

		def _callback(text: str):
			nonlocal _text
			nonlocal _is_callback_successful
			_text = text
			_is_callback_successful = True

		self.__read(
			delay_between_packets_seconds=delay_between_packets_seconds,
			callback=_callback,
			is_async=False
		)

		if not _is_callback_successful:
			raise Exception(f"Read process failed to block sync method before returning.")

		return _text

	def close(self):

		self.__read_write_socket.close()


class ClientSocketFactory():

	def __init__(self, *, to_server_packet_bytes_length: int, server_read_failed_delay_seconds: float, encryption: Encryption = None):

		self.__to_server_packet_bytes_length = to_server_packet_bytes_length
		self.__server_read_failed_delay_seconds = server_read_failed_delay_seconds
		self.__encryption = encryption

	def get_client_socket(self) -> ClientSocket:
		return ClientSocket(
			packet_bytes_length=self.__to_server_packet_bytes_length,
			read_failed_delay_seconds=self.__server_read_failed_delay_seconds,
			encryption=self.__encryption
		)


class ServerSocket():

	def __init__(self, *, to_client_packet_bytes_length: int, listening_limit_total: int, accept_timeout_seconds: float, client_read_failed_delay_seconds: float, encryption: Encryption = None):

		self.__to_client_packet_bytes_length = to_client_packet_bytes_length
		self.__listening_limit_total = listening_limit_total
		self.__accept_timeout_seconds = accept_timeout_seconds
		self.__client_read_failed_delay_seconds = client_read_failed_delay_seconds
		self.__encryption = encryption

		self.__host_ip_address = None  # type: str
		self.__host_port = None  # type: int
		self.__bindable_address = None
		self.__is_accepting = False
		self.__accepting_thread = None  # type: threading.Thread
		self.__accepting_socket = None
		self.__blocked_client_addresses = []

	def start_accepting_clients(self, *, host_ip_address: str, host_port: int, on_accepted_client_method):

		if self.__is_accepting:
			raise Exception("Cannot start accepting clients while already accepting.")
		else:

			self.__is_accepting = True

			self.__host_ip_address = host_ip_address
			self.__host_port = host_port
			self.__bindable_address = socket.getaddrinfo(self.__host_ip_address, self.__host_port, 0, socket.SOCK_STREAM)[0][-1]

			def _process_connection_thread_method(connection_socket, address, to_client_packet_bytes_length, on_accepted_client_method, client_read_failed_delay_seconds: float):

				if address not in self.__blocked_client_addresses:
					_accepted_socket = ClientSocket(
						packet_bytes_length=to_client_packet_bytes_length,
						read_failed_delay_seconds=client_read_failed_delay_seconds,
						socket=connection_socket,
						encryption=self.__encryption
					)
					_is_valid_client = on_accepted_client_method(_accepted_socket)
					if _is_valid_client == False:
						self.__blocked_client_addresses.append(address)

			def _accepting_thread_method(to_client_packet_bytes_length, on_accepted_client_method, listening_limit_total, accept_timeout_seconds, client_read_failed_delay_seconds):
				self.__accepting_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				self.__accepting_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				self.__accepting_socket.bind(self.__bindable_address)
				self.__accepting_socket.listen(listening_limit_total)
				self.__accepting_socket.settimeout(accept_timeout_seconds)
				while self.__is_accepting:
					try:
						_connection_socket, _address = self.__accepting_socket.accept()
						_connection_socket.setblocking(False)
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
				 encryption: Encryption = None):

		self.__to_client_packet_bytes_length = to_client_packet_bytes_length
		self.__listening_limit_total = listening_limit_total
		self.__accept_timeout_seconds = accept_timeout_seconds
		self.__client_read_failed_delay_seconds = client_read_failed_delay_seconds
		self.__encryption = encryption

	def get_server_socket(self) -> ServerSocket:

		return ServerSocket(
			to_client_packet_bytes_length=self.__to_client_packet_bytes_length,
			listening_limit_total=self.__listening_limit_total,
			accept_timeout_seconds=self.__accept_timeout_seconds,
			client_read_failed_delay_seconds=self.__client_read_failed_delay_seconds,
			encryption=self.__encryption
		)


class Module():

	def __init__(self):

		self._send_method = None

	def set_send_method(self, *, send_method):
		self._send_method = send_method

	def receive(self, *, data: str):
		raise NotImplementedError()


class ModuleLoader():

	def __init__(self, *, git_clone_directory_path: str):

		self.__git_clone_directory_path = git_clone_directory_path

		self.__module = None  # type: Module

	def load_module(self, *, git_clone_url: str, module_file_name: str, module_name: str):

		# clone git repo into directory

		os.chdir(self.__git_clone_directory_path)
		os.system("git clone " + git_clone_url)

		_module_file_path = os.path.join(self.__git_clone_directory_path, module_file_name)

		self.__module = get_module_from_file_path(_module_file_path)
