import ctypes
import os
import sys

# Windows vs others(cross platform compatibility:|)
if sys.platform.startswith("win"):
    lib_name = "native_core.dll"
elif sys.platform.startswith("darwin"):
    lib_name = "native_core.dylib"
else:
    lib_name = "native_core.so"


class ProcessTelemetry(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint64),
        ("ram_bytes", ctypes.c_double),
        ("thread_count", ctypes.c_uint64),
        ("open_handles", ctypes.c_uint64),
    ]


def run_audit(data_list):
    if not data_list:
        return []

    try:
        # Resolve path and pull library first
        dir_path = os.path.dirname(os.path.abspath(__file__))
        lib_path = os.path.join(dir_path, lib_name)
        backend = ctypes.CDLL(lib_path)

        # Allocate memory block for our structures
        size = len(data_list)
        telemetry_array = (ProcessTelemetry * size)()
        for i, val in enumerate(data_list):
            telemetry_array[i] = ProcessTelemetry(val[0], val[1], val[2], val[3])

        # Setup C buffers for returns
        alert_buffer = (ctypes.c_uint64 * size)()
        alert_count = ctypes.c_int(0)

        backend.process_telemetry_stream(
            telemetry_array, size, alert_buffer, ctypes.byref(alert_count)
        )

        return [alert_buffer[x] for x in range(alert_count.value)]

    except Exception as e:
        return f"Audit failed: {str(e)}"


if __name__ == "__main__":
    # our whitelisted system telemetry and an actual imposter
    sample_data = [
        [76, 45000000.0, 0, 120], 
        [999, 85000000.0, 0, 15]
    ]

    print(f"Flagged PIDs: {run_audit(sample_data)}")
