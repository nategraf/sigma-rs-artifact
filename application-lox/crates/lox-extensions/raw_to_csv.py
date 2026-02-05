from pathlib import Path
import re
import statistics

def parse_files(log, file):
    for line in log:
        file.write(line)
    file.close()

def handle_timing_values(unit):
    raw_size = 0.0
    if "µ" in unit:
        micro_sec = unit.split("µ")
        raw_size = float(micro_sec[0])*0.001
    elif "m" not in unit:
        sec = unit[:-3]
        raw_size = float(sec)*1000
    else:
        raw_size = float(unit[:-3])

    return raw_size

# Combine all log files for each protocol into a single
# <protocol-name>.log file
for p in Path('./parsed_results').glob('*.log'):
    print(f"Parsing: {p.name.strip('.log')}\n")
    with p.open() as log_file:
        fname = re.sub(r'[0-9]', '', p.name.strip('.log'))
        try:
            with open("./parsed_results/"+fname+".log", "x") as file:
                print("Creating new file: "+fname+".log")
                parse_files(log_file, file)

        except FileExistsError:
            print("Writing to exisiting file: "+fname+".log")
            with open("./parsed_results/"+fname+".log", "a") as file:
                parse_files(log_file, file)
    p.unlink()

req_size = 0
req_t = []
resp_size = 0
resp_t = []
resphandle_t = []
protobytes_file = open("./parsed_results/protocol-bytes"+".csv", "w")
protobytes_file.write("Protocol,Request Size,Reply Size\n")
timings_file = open("./parsed_results/native-ms"+".csv", "w")
timings_file.write("Protocol, Client, σ, Server, σ, Client, σ\n")

# Parse the values for request size/time, reply size/time and
# reply handling size/time for each protocol and add to csv file
for p in Path('./parsed_results').glob('*.log'):
    filename = p.name.strip('.log')
    with p.open() as logfile:
        for line in logfile:
            if "Request size" in line:
                num = line.split("=")
                req_size = num[1].strip().split(" ")[0]
            if "Request time" in line:
                num = line.split("=")
                val = handle_timing_values(num[1])
                req_t.append(float(val))
            if "Response size" in line:
                num = line.split("=")
                resp_size = num[1].strip().split(" ")[0]
            if "Response time" in line:
                num = line.split("=")
                resp_time = num[1].strip().split(" ")[0]
                val = handle_timing_values(num[1])
                resp_t.append(float(val))
            if "Response handle time" in line:
                num = line.split("=")
                resp_handle_time = num[1].split(" ")[0]
                val = handle_timing_values(num[1])
                resphandle_t.append(float(val))
    req_time = round((sum(req_t) / len(req_t)), 2)
    resp_time = round((sum(resp_t) / len(resp_t)), 2)
    resp_handle_time = round((sum(resphandle_t) / len(resphandle_t)), 2)
    req_time_std = round(statistics.stdev(req_t), 2)
    resp_time_std = round(statistics.stdev(resp_t), 2)
    resp_handle_std = round(statistics.stdev(resphandle_t), 2)
    protobytes_file.write(filename.replace("_", " ", 1)+","+str(req_size)+","+str(resp_size)+"\n")
    timings_file.write(filename.replace("_", " ", 1)+","+str(req_time+resp_handle_time)+","+str(req_time_std+resp_handle_std)+","+str(resp_time)+","+str(resp_time_std)+", ,\n")
    p.unlink()

protobytes_file.close()
timings_file.close()
print("Wrote native-ms.csv.")


