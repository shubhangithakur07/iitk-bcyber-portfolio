import ctypes
import os

# Define the structure identically to the C-layer layout
class ProcessTelemetry(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint64),
        ("ram_bytes", ctypes.c_double),
        ("thread_count", ctypes.c_uint64),
        ("open_handles", ctypes.c_uint64)
    ]

def execute_native_core_audit(mock_data_list):
    """Bridges high-level Python arrays into raw C memory buffers."""
    try:
        # Load the compiled hardware-level shared binary
        lib_path = os.path.abspath("./native_core.dll")
        native_lib = ctypes.CDLL(lib_path)
        
        # Define arguments: array pointer, size, alert buffer pointer, alert count pointer
        native_lib.process_telemetry_stream.argtypes = [
            ctypes.POINTER(ProcessTelemetry),
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_int)
        ]
        
        # Populate the C-compatible structural buffer
        data_count = len(mock_data_list)
        c_array = (ProcessTelemetry * data_count)(* [
            ProcessTelemetry(pid=d[0], ram_bytes=d[1], thread_count=d[2], open_handles=d[3])
            for d in mock_data_list
        ])
        
        alert_buffer = (ctypes.c_uint64 * data_count)()
        alert_count = ctypes.c_int(0)
        
        # Execute natively inside the compiled binary memory space
        native_lib.process_telemetry_stream(c_array, data_count, alert_buffer, ctypes.byref(alert_count))
        
        return [alert_buffer[i] for i in range(alert_count.value)]
    except Exception as e:
        return f"Native execution context offline (Compilation required): {str(e)}"

if __name__ == "__main__":
    # Test Data: PID 76 (Whitelisted), PID 999 (True Malicious Orphaned Process)
    sample_stream = [
        [76, 45000000.0, 0, 120],
        [999, 85000000.0, 0, 15]
    ]
    print(f"[*] Detected Vulnerable PIDs via Native C Core: {execute_native_core_audit(sample_stream)}")