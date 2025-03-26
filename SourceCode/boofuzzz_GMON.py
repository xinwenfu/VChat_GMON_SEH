#!/usr/bin/env python  # Uses the env command to locate the Python interpreter in the system's PATH environment variable
from boofuzz import *  # Imports everything from the boofuzz module, making functions and classes available without a prefix
import sys  # Imports the sys module to interact with the system (e.g., exit the script)

# Function to receive a banner message from the target system (typically used for services that send a welcome message)
def receive_banner(sock):
    sock.recv(1024)  # Reads up to 1024 bytes from the socket but doesn't store or process them

# Main function to set up and start fuzzing
def main():
    host = '10.0.2.15'  # Target host (IP address of the machine running the vulnerable service)
    port = 9999  # Target port (port number of the service to fuzz)

    # Create different loggers for tracking fuzzing progress
    text_logger = FuzzLoggerText()  # Logs fuzzing progress to the console
    file_logger = FuzzLoggerText(open("fuzz_log.txt", "w"))  # Logs fuzzing progress to a text file
    csv_logger = FuzzLoggerCsv(open("fuzz_log.csv", "w", newline=""))  # Logs fuzzing progress to a CSV file

    # Initialize a fuzzing session
    session = Session(
        sleep_time=1,  # Wait 1 second between each fuzz case
        target=Target(connection=TCPSocketConnection(host, int(port))),  # Set up a TCP connection to the target
        reuse_target_connection=True,  # Reuse the same connection for multiple fuzz cases
        fuzz_loggers=[text_logger, file_logger, csv_logger]  # Use the specified loggers to record fuzzing data
    )

    # Define the fuzzing structure for the "TRUN" command
    s_initialize("GMON")  # Initialize a fuzzing block named "TRUN"
    s_string('GMON', fuzzable=False, name='GMON-Command')  # Send the command "TRUN" (not fuzzable)
    s_delim(' ', fuzzable=False, name='GMON-Space')  # Send a space after "TRUN" (not fuzzable)
    s_string('A', name='GMON-STRING')  # Fuzz this part by sending different "A" variations
    s_static('\r\n', name='GMON-CRLF')  # Append a carriage return + newline to mimic real commands

    session.pre_send = receive_banner  # Assign `receive_banner` as a pre-send callback to read any initial response

    session.connect(s_get("GMON"))  # Connect the fuzzing session to the "TRUN" structure defined above

    session.fuzz()  # Start the fuzzing process

# Entry point for the script
if __name__ == '__main__':
    main()  # Call the main function if the script is run directly, not when it is imported as a module.
