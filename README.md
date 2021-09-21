**Installation**
```
$ pip install git+https://github.com/AustinHellerRepo/Socket
```

**Usage**
1. Starting a server and connecting a client
```
from austin_heller_repo.socket import ServerSocket, ClientSocket

_server_socket = ServerSocket(
  to_client_packet_bytes_length=4096,
  listening_limit_total=3,
  accept_timeout_seconds=0.5,
  client_read_failed_delay_seconds=0.1
)

def _on_accepted_client_method(client_socket: ClientSocket):
  client_socket.write("hello")
  client_socket.close()

_server_socket.start_accepting_clients(
  host_ip_address="0.0.0.0",
  host_port=28573,
  on_accepted_client_method=_on_accepted_client_method
)

_client_socket = ClientSocket(
  packet_bytes_length=4096,
  read_failed_delay_seconds=0.1
)

_client_socket.connect_to_server(
  ip_address="0.0.0.0",
  port=28573
)

_message = _client_socket.read()

print("message: \"" + _message + "\"")

_server_socket.stop_accepting_clients()
_server_socket.close()
_client_socket.close()
```
