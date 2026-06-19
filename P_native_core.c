/* * SECURITY ENGINE CORE - TELEMETRY AUDIT
 * Author: Shubhangithakur07
 * Project:ProcAudit-Engine( IITK Portfolio Submission)
 */

#include <stdio.h>
#include <stdint.h>

#define PID_KERNEL 4
#define PID_SYSTEM 76

/* 
 * Cross-platform compatibility check 
 * total struc size made to be 32bytes -precisely!
 */
typedef struct {
    uint64_t pid;
    double ram_bytes;
    uint64_t thread_count;
    uint64_t open_handles;
} ProcessTelemetry;

/* 
 * we'll scan for processes with memory usage but 0 active threads.
 * also filter out our whitelists to minimize false positives.
 */
void process_telemetry_stream(const ProcessTelemetry* stream, int row_count, uint64_t* critical_alerts, int* alert_count) {
    if (!stream || !critical_alerts || !alert_count) return;
    
    *alert_count = 0;
    
    for (int i = 0; i < row_count; i++) {
        // zero thread activity but have memry footprint
        if (stream[i].thread_count == 0 && stream[i].ram_bytes > 0) {
            
            // Skip infrastructure processes (Kernel and System)
            if (stream[i].pid == PID_KERNEL || stream[i].pid == PID_SYSTEM) {
                continue; 
            }
            
    
            critical_alerts[*alert_count] = stream[i].pid;
            (*alert_count)++;
        }
    }
}
