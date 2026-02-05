from pathlib import Path
import os
import statistics

def parse_files(log, file):
     for line in log:
         if "Dump buffer:" in line:
             file.write(line)
     file.close()

def handle_timing_values(unit):
    unit.strip(" ")
    raw_size = 0.0
    if "µ" in unit:
        micro_sec = unit.split("µ")
        raw_size = float(micro_sec[0])*0.001
    elif "m" not in unit:
        sec = unit[:-3]
        raw_size = float(sec)*1000
    else:
        raw_size = unit[:-2]

    return raw_size

# Combine all log files for each protocol into a single
# <protocol-name>.log file
try:
   os.remove("./console_logs/dump.log")
except OSError:
   pass
for p in Path('./console_logs/').glob('*.log'):
    print(f"Parsing: {p.name.strip('.log')}\n")
    with p.open() as log_file:
        try:
            with open("./console_logs/dump.log", "x") as file:
                print("Creating new file: dump.log")
                parse_files(log_file, file)

        except FileExistsError:
            print("Writing to existing file: dump.log")
            with open("./console_logs/dump.log", "a") as file:
                parse_files(log_file, file)

try:
    timings_file = open("./console_logs/wasm-ms"+".csv", "w")
    timings_file.write("Protocol,Client, σ\n")
except FileNotFoundError:
    print("Unable to create csv file for wasm measurements")
    exit()
open_invite_r = []
open_invite_h = []
trust_promotion_r = []
trust_promotion_h = []
migration_r = []
migration_h = []
level_up_r = []
level_up_h = []
issue_invite_r = []
issue_invite_h = []
redeem_invite_r = []
redeem_invite_h = []
check_blockage_r = []
check_blockage_h = []
blockage_migration_r =[]
blockage_migration_h =[]
update_cred_r = []
update_cred_h = []
update_invite_r = []
update_invite_h = []

# Parse the values for request size/time, reply size/time and
# reply handling size/time for each protocol and add to csv file
with open("./console_logs/dump.log", "r") as logfile:
    for line in logfile:
        num = line.split("time")
        only_num = num[1].split('" ')
        val = handle_timing_values(only_num[0])
        if "open-invite" in num[0]:
            if "request" in num[0]:
                open_invite_r.append(float(val))
            else:
                open_invite_h.append(float(val))
        if "trust-promo" in num[0]:
            if "request" in num[0]:
                trust_promotion_r.append(float(val))
            else:
                trust_promotion_h.append(float(val))
        if "migration" in num[0]:
            if "request" in num[0]:
                migration_r.append(float(val))
            else:
                migration_h.append(float(val))
        if "level-up" in num[0]:
            if "request" in num[0]:
                level_up_r.append(float(val))
            else:
                level_up_h.append(float(val))
        if "issue-invite" in num[0]:
            if "request" in num[0]:
                issue_invite_r.append(float(val))
            else:
                issue_invite_h.append(float(val))
        if "redeem-invite" in num[0]:
            if "request" in num[0]:
                redeem_invite_r.append(float(val))
            else:
                redeem_invite_h.append(float(val))
        if "check-blockage" in num[0]:
            if "request" in num[0]:
                check_blockage_r.append(float(val))
            else:
                check_blockage_h.append(float(val))
        if "blockage-migration" in num[0]:
            if "request" in num[0]:
                blockage_migration_r.append(float(val))
            else:
                blockage_migration_h.append(float(val))
        if "update-cred" in num[0]:
            if "request" in num[0]:
                update_cred_r.append(float(val))
            else:
                update_cred_h.append(float(val))
        if "update-invite" in num[0]:
            if "request" in num[0]:
                update_invite_r.append(float(val))
            else:
                update_invite_h.append(float(val))

open_inv = list(map(lambda x, y: x + y, open_invite_h, open_invite_r))
openinvite_time = round((sum(open_inv))/(len(open_invite_r)), 2)
oi_std = round(statistics.stdev(open_inv), 2)

trust_promo = list(map(lambda x, y: x + y, trust_promotion_h, trust_promotion_r))
trustpromo_time = round((sum(trust_promo))/(len(trust_promotion_r)), 2)
tp_std = round(statistics.stdev(trust_promo), 2)

mig = list(map(lambda x, y: x + y, migration_h, migration_r))
mig_time = round((sum(mig))/(len(migration_r)), 2)
mi_std = round(statistics.stdev(mig), 2)

level = list(map(lambda x, y: x + y, level_up_h, level_up_r))
level_time = round((sum(level))/(len(level_up_r)), 2)
lu_std = round(statistics.stdev(level), 2)

issue = list(map(lambda x, y: x + y, issue_invite_h, issue_invite_r))
issue_time = round((sum(issue))/(len(issue_invite_r)), 2)
ii_std = round(statistics.stdev(issue), 2)

redeem = list(map(lambda x, y: x + y, redeem_invite_h, redeem_invite_r))
redeem_time = round((sum(redeem))/(len(redeem_invite_r)), 2)
ri_std = round(statistics.stdev(redeem), 2)

checkb = list(map(lambda x, y: x + y, check_blockage_h, check_blockage_r))
checkb_time = round((sum(checkb))/(len(check_blockage_r)), 2)
cb_std = round(statistics.stdev(checkb), 2)

blockm = list(map(lambda x, y: x + y, blockage_migration_h, blockage_migration_r))
blockm_time = round((sum(blockm))/(len(blockage_migration_r)),2)
bm_std = round(statistics.stdev(blockm), 2)

updatec = list(map(lambda x, y: x + y, update_cred_h, update_cred_r))
updatec_time = round((sum(updatec))/(len(update_cred_r)),2)
uc_std = round(statistics.stdev(updatec), 2)

updatei = list(map(lambda x, y: x + y, update_invite_h, update_invite_r))
updatei_time = round((sum(updatei))/(len(update_invite_r)), 2)
ui_std = round(statistics.stdev(updatei), 2)


timings_file.write("Open Invitation,"+str(openinvite_time)+","+str(oi_std)+"\n")
timings_file.write("Trust Promotion,"+str(trustpromo_time)+","+str(tp_std)+"\n")
timings_file.write("Migration,"+str(mig_time)+","+str(mi_std)+"\n")
timings_file.write("Level Up,"+str(level_time)+","+str(lu_std)+"\n")
timings_file.write("Issue Invite,"+str(issue_time)+","+str(ii_std)+"\n")
timings_file.write("Redeem Invite,"+str(redeem_time)+","+str(ri_std)+"\n")
timings_file.write("Check Blockage,"+str(checkb_time)+","+str(cb_std)+"\n")
timings_file.write("Blockage Migration,"+str(blockm_time)+","+str(bm_std)+"\n")
timings_file.write("Update Cred,"+str(updatec_time)+","+str(uc_std)+"\n")
timings_file.write("Update Invite,"+str(updatei_time)+","+str(ui_std)+"\n")

timings_file.close()
print("Wrote wasm-ms.csv.")
