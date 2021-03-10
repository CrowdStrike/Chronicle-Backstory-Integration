'''
Copyright CrowdStrike 2020. See LICENSE for more information.
'''
from os import _exit
from os import path
from time import time, sleep
from datetime import datetime
from requests import request, get
from json import dumps, dump, loads, load
from threading import Thread
from signal import signal, SIGINT
from urllib.parse import quote
from socket import gethostname
from logging import basicConfig, error, DEBUG

basicConfig(filename='crowdstrike-chronicle-client-logs.log', level=DEBUG)


class ChronicleClient():
    def __init__(self):
        # default offset to high value to get all streams
        self.default_offset = 999999999
        self.offsets = dict()
        self.streamsStarted = False
        # get client credentials
        self.clientId = input("Enter CrowdStrike Client ID: ")
        self.clientSecret = input("Enter CrowdStrike Client Secret: ")
        # get chronicle credentials
        self.googleSecKey = input("Enter Google Security Key: ")
        # define signal interrupt code

        def signal_handler(sig, frame):
            self.handle_exit(0, "exiting...")
        signal(SIGINT, signal_handler)
        print('ctrl+c to quit')
        # call main function
        self.main()

    def get_streams(self):
        try:
            attempt = 0
            # init
            appId = "ChronicleClient"
            discoverURL = "https://api.crowdstrike.com:443/sensors/entities/datafeed/v2?appId=" + appId
            headers = {'Authorization': 'bearer ' +
                       self.token, 'Accept': 'application/json'}
            # parse response
            r = get(discoverURL, headers=headers)
            # log api errors to chronicle
            while (r.status_code >= 400):
                attempt += 1
                if (attempt > 2):
                    self.handle_exit(1, "error discovering streams")
                self.log_to_chronicle(r.json(), self.map_error_to_udm)
                error("error discovering streams, retrying in 1 minute: " + r.text)
                sleep(60)
                r = get(discoverURL, headers=headers)
            response = r.json()
            return response
        except:
            self.handle_exit(1, "error discovering streams")

    def handle_exit(self, code, message):
        if (code == 1):
            error(message)
        if (self.streamsStarted):
            try:
                with open('offset.json', 'w') as f:
                    dump(self.offsets, f)
            except:
                error("offset.json not found")
        _exit(code)

    def log_to_chronicle(self, response, mapper):
        try:
            attempt = 0
            headers = {'Content-Type': 'application/json'}
            payload = {"events": [mapper(response)]}
            r = request("POST", "https://malachiteingestion-pa.googleapis.com/v1/udmevents?key=" +
                        self.googleSecKey, data=dumps(payload), headers=headers)
            while (r.status_code >= 400):
                attempt += 1
                if (attempt > 2):
                    self.handle_exit(1, "error logging to chronicle")
                error("error logging to chronicle, retrying in 10 seconds: " + r.text)
                sleep(10)
                r = request("POST", "https://malachiteingestion-pa.googleapis.com/v1/udmevents?key=" +
                            self.googleSecKey, data=dumps(payload), headers=headers)
        except:
            self.handle_exit(1, "error logging to chronicle")

    def main(self):
        # get token
        self.refresh_token()
        # read offset from file
        self.read_offset()
        # get streams
        response = self.get_streams()
        # start thread for each stream in environment
        threads = []
        i = 0
        try:
            for stream in response['resources']:
                i = i + 1
                # get urls and stream token
                data_url = stream['dataFeedURL']
                refreshURL = stream['refreshActiveSessionURL']
                token = stream['sessionToken']['token']
                if data_url in self.offsets:
                    offset = self.offsets[data_url]
                else:
                    offset = self.default_offset
                # start thread
                threads.append(Thread(target=self.stream, args=(
                    data_url, token, offset, refreshURL)))
                threads[-1].start()
                sleep(1)
            for t in threads:
                # join threads
                t.join()
        except:
            self.handle_exit(1, "failed to get stream token")

    def map_detection_to_udm(self, detectionEvent):
        timestampComponents = str(datetime.fromtimestamp(
            detectionEvent["event"]["ProcessStartTime"])).split()
        newURL = self.parse_url(detectionEvent["event"]["FalconHostLink"])
        udmResult = {
            "metadata": {
                "event_timestamp": timestampComponents[0]+"T"+timestampComponents[1]+"+00:00",
                "event_type": "PROCESS_UNCATEGORIZED",
                "description": detectionEvent["event"]["DetectDescription"],
                "product_event_type": detectionEvent["metadata"]["eventType"],
                "product_log_id": detectionEvent["event"]["DetectId"],
                "product_name": "Falcon"
            },
            "principal": {
                "hostname": detectionEvent["event"]["ComputerName"],
                "user": {
                    "userid": detectionEvent["event"]["UserName"]
                },
                "ip": detectionEvent["event"]["LocalIP"]
            },
            "target": {
                "asset_id": "CrowdStrike.Falcon:"+detectionEvent["event"]["SensorId"],
                "process": {
                    "command_line": detectionEvent["event"]["CommandLine"],
                    "file": {
                        "full_path": detectionEvent["event"]["FilePath"] + "\\" + detectionEvent["event"]["FileName"],
                        "md5": detectionEvent["event"]["MD5String"],
                        "sha1": detectionEvent["event"]["SHA1String"],
                        "sha256": detectionEvent["event"]["SHA256String"]
                    },
                    "pid": str(detectionEvent["event"]["ProcessId"]),
                    "parent_process": {
                        "command_line": detectionEvent["event"]["ParentCommandLine"],
                        "pid": str(detectionEvent["event"]["ParentProcessId"])
                    }
                }
            },
            "security_result": {
                "action_details": detectionEvent["event"]["PatternDispositionDescription"],
                "severity_details": detectionEvent["event"]["SeverityName"],
                "url_back_to_product": newURL
            }
        }
        return udmResult

    def map_error_to_udm(self, response):
        timestampComponents = str(datetime.fromtimestamp(int(time()))).split()
        errorLog = {
            "metadata": {
                "event_timestamp": timestampComponents[0]+"T"+timestampComponents[1]+"+00:00",
                "event_type": "PROCESS_UNCATEGORIZED",
                "description": str(response["errors"][0]["code"]) + ": " + response["errors"][0]["message"],
                "product_event_type": "CrowdStrikeEventStreamError",
                "product_log_id": response["meta"]["trace_id"],
                "product_name": "Falcon"
            },
            "principal": {
                "hostname": gethostname(),
                "ip": '127.0.0.1'
            },
            "target": {
                "process": {
                    "pid": "N/A",
                }
            },
        }
        return errorLog

    def read_offset(self):
        try:
            if (path.exists("offset.json")):
                with open("offset.json") as json_file:
                    self.offsets = load(json_file)
            else:
                self.offsets = {}
                f = open("offset.json", "x")
                dump(self.offsets, f)
        except:
            error("could not open offset file")

    def parse_url(self, url):
        try:
            cid = url.split("_")[-1]
            segments = url.split("/")
            relevantURL = ""
            for i in range(3, len(segments)):
                relevantURL += "/" + segments[i]
            parsedRelevantURL = quote(relevantURL, safe='')
            finalURL = segments[0]+"/"+segments[1]+"/" + \
                segments[2]+"/api2/link?"+cid+"&url="+parsedRelevantURL
            return finalURL.split("_")[0]
        except:
            return url

    def refresh_stream(self, refreshURL):
        try:
            attempt = 0
            # send refresh request
            headers = {'Authorization': 'bearer %s' % self.token,
                       'Accept': 'application/json', 'Content-Type': 'application/json'}
            payload = {'action_name': 'refresh_active_stream_session',
                       'appId': 'my_app_id'}
            r = request("POST", refreshURL, data=payload, headers=headers)
            # log api errors to chronicle
            while (r.status_code >= 400):
                attempt += 1
                if (attempt > 2):
                    self.handle_exit(1, "error refreshing stream")
                self.log_to_chronicle(r.json(), self.map_error_to_udm)
                error("error refreshing stream, retrying in 1 minute: " + r.text)
                sleep(60)
                r = request("POST", refreshURL, data=payload, headers=headers)
        except:
            self.handle_exit(1, "error refreshing stream")

    def refresh_token(self):
        try:
            attempt = 0
            # init
            url = 'https://api.crowdstrike.com/oauth2/token'
            payload = 'client_id='+self.clientId+'&client_secret='+self.clientSecret
            tokenHeaders = {
                'content-type': 'application/x-www-form-urlencoded'}
            # parse response
            r = request("POST", url, data=payload, headers=tokenHeaders)
            # log api errors to chronicle
            while (r.status_code >= 400):
                attempt += 1
                if (attempt > 2):
                    self.handle_exit(1, "error refreshing token")
                self.log_to_chronicle(r.json(), self.map_error_to_udm)
                error("error refreshing token, retrying in 1 minute: " + r.text)
                sleep(60)
                r = request("POST", url, data=payload, headers=tokenHeaders)
            r = r.json()
            token = r['access_token']
            self.token = token
            # set token period start time
            self.token_period_start = time()
        except:
            self.handle_exit(1, "error refreshing token")

    def stream(self, url, token, offset, refreshURL):
        # @param url: the stream url
        # @param token: the stream token
        # @param offset: the offset to begin at
        # @param refreshURL: the url to refresh the stream
        try:
            # connect to stream url
            attempt = 0
            stream_period_start = time()
            requrl = url + "&offset=%s" % offset
            headers = {'Authorization': 'Token %s' % token,
                       'Connection': 'Keep-Alive'}
            r = get(requrl, headers=headers, stream=True)
            # log stream errors to chronicle
            while (r.status_code >= 400):
                attempt += 1
                if (attempt > 2):
                    self.handle_exit(1, "error connecting to stream")
                self.log_to_chronicle(r.json(), self.map_error_to_udm)
                error("error connecting to stream, retrying in 1 minute: " + r.text)
                sleep(60)
                r = get(requrl, headers=headers, stream=True)
            # flag that streams have started
            self.streamsStarted = True
            for line in r.iter_lines():
                # check new streams
                if line:
                    decoded_line = line.decode('utf-8')
                    decoded_line = loads(decoded_line)
                    self.offsets[url] = decoded_line['metadata']['offset']
                    # log to detections to chronicle
                    if (decoded_line['metadata']['eventType'] == "DetectionSummaryEvent"):
                        self.log_to_chronicle(
                            decoded_line, self.map_detection_to_udm)
                # refresh stream after 25 minutes
                if (time() - stream_period_start >= 1500):
                    stream_period_start = time()
                    self.refresh_stream(refreshURL)
                # refresh token after 25 minutes
                if (time() - self.token_period_start >= 1500):
                    self.refresh_token()
        except:
            self.handle_exit(1, "error reading last stream chunk")


def main():
    ChronicleClient()


if __name__ == "__main__":
    main()
