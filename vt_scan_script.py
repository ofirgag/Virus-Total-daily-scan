import requests
import schedule
import time
from datetime import date
import json

key = '87f145f4d7dadc4a93a1120a800c0c72f7fb4b7c818f44a353f33d06ac6b1811'


def vt_request(curr_hash):
    params = {'apikey': key, 'resource': curr_hash}
    r = requests.post('https://www.virustotal.com/vtapi/v2/file/report', data=params)
    response = int(json.loads(r.text).get('response_code'))
    if response == 0:
        return 0
    elif response == 1:
        positives = int(json.loads(r.text).get('positives'))
        if positives < 5:
            return 1
        else:
            return 2
    else:
        return 0


def job():
    # open sha1_file of sha1
    print('job started')
    date_ = date.today()
    sha1_file = open('/DATA/Ofir/VT/sha1/' + str(date_) + '.txt')
    mal_file = open('/DATA/Ofir/VT/mal/' + str(date_) + '.txt', 'w+')
    benign_file = open('/DATA/Ofir/VT/benign/' + str(date_) + '.txt', 'w+')
    not_known_file = open('/DATA/Ofir/VT/not known/' + str(date_) + '.txt', 'w+')
    stats_file = open('/DATA/Ofir/VT/VT stats/' + str(date_) + '.txt', 'w+')
    mal_count = 0
    benign_count = 0

    # read 20k files and store them in list.

    sha1_lst = []
    for row in sha1_file:
        sha1_lst.append(row)

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


schedule.every().day.at("12:10").do(job)

if __name__ == "__main__":
    while 1:
        schedule.run_pending()
        time.sleep(1)  # wait one sec
