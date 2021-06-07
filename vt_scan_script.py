import requests
import schedule
import time
from datetime import date
import json

key = '<Your API key>'


def vt_request(curr_hash, threshold=5):
    params = {'apikey': key, 'resource': curr_hash}
    r = requests.post('https://www.virustotal.com/vtapi/v2/file/report', data=params)
    response = int(json.loads(r.text).get('response_code'))
    if response == 0:
        return 0
    elif response == 1:
        positives = int(json.loads(r.text).get('positives'))
        # In case threshold or more anti virus detected the file, mark it as malicious. Else, mark it as benign.
        if positives < threshold:
            return 1
        else:
            return 2
    return 0


def job():
    # open sha1_file of sha1
    print('job started')
    date_ = date.today()
    sha1_file = open('<The path to the file you want to scan today>')
    mal_file = open('<The path to the file of the files detected as malicious>', 'w+')
    benign_file = open('<The path to the file of the files detected as benign>', 'w+')
    not_known_file = open('<The path to the file of the files detected as unknown>', 'w+')
    stats_file = open('<The path to the statistics file>', 'w+')

    mal_count = 0
    benign_count = 0

    # read k files and store them in list.
    # k shouldn't be larger than the maximum capacity VT allows you to scan each day
    # read 20k files and store them in list.

    sha1_lst = [row for row in sha1_file]

    # iterate list and call vt_request
    # iterate results and save statistics

    for sha1 in sha1_lst:
        result = vt_request(sha1)
        if result == 0:
            not_known_file.write(sha1)
        elif result == 1:
            benign_file.write(sha1)
            benign_count += 1
        else:
            mal_file.write(sha1)
            mal_count += 1

    stats_file.write('mal_count: ' + str(mal_count) + '\n' + 'benign_count: ' + str(
        benign_count) + '\n' + 'mal_percentage: ' + str(
        float(mal_count) / (float(mal_count) + float(benign_count)) * 100) + '\n')

    stats_file.close()
    sha1_file.close()
    mal_file.close()
    benign_file.close()
    stats_file.close()

    print('Finished job for day: ' + str(date_))


schedule.every().day.at("<The hour you want the scan to start on each day>").do(job)

if __name__ == "__main__":
    while 1:
        schedule.run_pending()
        time.sleep(1)  # wait one sec
