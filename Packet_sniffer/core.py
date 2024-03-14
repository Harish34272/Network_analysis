import itertools
import time
from socket import PF_PACKET, SOCK_RAW, ntohs, socket
from typing import Iterator

import netprotocols
import joblib  
model = joblib.load('knn_model.pkl')

class Decoder:
    def __init__(self, interface: str):
        self.interface = interface
        self.data = None
        self.protocol_queue = ["Ethernet"]
        self.packet_num: int = 0
        self.frame_length: int = 0
        self.epoch_time: float = 0
    def _bind_interface(self, sock: socket):
        """Bind the socket to a given interface's address, if any.

        :param sock: A socket object whose methods implement the various
        socket system calls.
        """
        if self.interface is not None:
            sock.bind((self.interface, 0))
    def _extract_features(self, payload):
        payload_length = len(payload)
        num_unique_characters = len(set(payload))
        extracted_features = [payload_length, num_unique_characters]
        return extracted_features
    def _predict(self, features):
       
        prediction = model.predict(features.reshape(1, -1))  # Reshape features if needed
        return prediction

    def _inspect_payload(self):
        if hasattr(self, 'tcp') and hasattr(self, 'udp') and self.tcp.payload_len > 0:
            # Perform DPI on TCP payload
            payload_data = self.data[:self.tcp.payload_len]
            # Add your DPI analysis logic here
            print(f"[+] DPI Analysis: {payload_data.decode(errors='ignore')}")
            features = self._extract_features(payload_data)
            prediction = self._predict(features)
            if prediction == "normal":
             print("[+] Traffic is normal")
            else:
              print("[+] Traffic is an anomaly")
            #print(f"[+] Prediction: {prediction}")
            #print(f"{self._indentation}[+] DPI Analysis: {payload_data.decode(errors='ignore')}")
    def _attach_protocols(self, frame: bytes):
        """Dynamically attach protocols as instance attributes.

        A given frame containing Ethernet, IP and TCP protocols, for
        example, will be decoded and the present instance will contain
        the attributes self.ethernet, self.ip and self.tcp, all of which
        are, by themselves, instances of netprotocols.Protocol.

        :param frame: A sequence of bytes representing the data received
            from a socket object.
        """
        start = end = 0
        for proto in self.protocol_queue:
            try:
                proto_class = getattr(netprotocols, proto)
            except AttributeError:
                continue
            end: int = start + proto_class.header_len
            protocol = proto_class.decode(frame[start:end])
            setattr(self, proto.lower(), protocol)
            if protocol.encapsulated_proto in (None, "undefined"):
                break
            self.protocol_queue.append(protocol.encapsulated_proto)
            start = end
        self.data = frame[end:]
    def execute(self, indentation: str = " ") -> Iterator:
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0003)) as sock:
            self._bind_interface(sock)
            for self.packet_num in itertools.count(1):
                self.frame_length = len(frame := sock.recv(9000))
                self.epoch_time = time.time_ns() / (10 ** 9)
                self._attach_protocols(frame)
                self._inspect_payload()  
                yield self
                del self.protocol_queue[1:]
   
class PacketSniffer:
    def __init__(self):
        """Monitor a network interface for incoming data, decode it and
        send to pre-defined output methods."""
        self._observers = list()

    def register(self, observer) -> None:
        """Register an observer for processing/output of decoded
        frames.

        :param observer: Any object that implements the interface
        defined by the Output abstract base-class."""
        self._observers.append(observer)

    def _notify_all(self, *args, **kwargs) -> None:
        """Send a decoded frame to all registered observers for further
        processing/output."""
        [observer.update(*args, **kwargs) for observer in self._observers]

    def listen(self, interface: str) -> Iterator:
        """Directly output a captured Ethernet frame while
        simultaneously notifying all registered observers, if any.

        :param interface: Interface from which a given frame will be
            captured and decoded.
        """
        for frame in Decoder(interface).execute():
            self._notify_all(frame)
            yield frame