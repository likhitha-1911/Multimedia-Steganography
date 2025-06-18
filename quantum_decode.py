import numpy as np

class QuantumDecoder:
    def __init__(self):
        self.measurements = []
        
    def decode_message(self, states):
        """Decode message from simulated quantum states"""
        binary_msg = []
        
        for state in states:
            # Measure the quantum state (simplified)
            if abs(state[0]) > abs(state[1]):
                binary_msg.append('0')
            else:
                binary_msg.append('1')
                
        # Convert binary to text
        message = ''
        for i in range(0, len(binary_msg), 8):
            byte = binary_msg[i:i+8]
            if len(byte) == 8:
                message += chr(int(''.join(byte), 2))
                
        return {
            'message': message,
            'measurements': len(binary_msg)
        }