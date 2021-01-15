'''
Copyright CrowdStrike 2020

By accessing or using this script, sample code, application programming interface, tools, and/or associated documentation (if any) (collectively, “Tools”), You (i) represent and warrant that You are entering into this Agreement on behalf of a company, organization or another legal entity (“Entity”) that is currently a customer or partner of CrowdStrike, Inc. (“CrowdStrike”), and (ii) have the authority to bind such Entity and such Entity agrees to be bound by this Agreement.

CrowdStrike grants Entity a non-exclusive, non-transferable, non-sublicensable, royalty free and limited license to access and use the Tools solely for Entity’s internal business purposes and in accordance with its obligations under any agreement(s) it may have with CrowdStrike. Entity acknowledges and agrees that CrowdStrike and its licensors retain all right, title and interest in and to the Tools, and all intellectual property rights embodied therein, and that Entity has no right, title or interest therein except for the express licenses granted hereunder and that Entity will treat such Tools as CrowdStrike’s confidential information.

THE TOOLS ARE PROVIDED “AS-IS” WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY OR OTHERWISE. CROWDSTRIKE SPECIFICALLY DISCLAIMS ALL SUPPORT OBLIGATIONS AND ALL WARRANTIES, INCLUDING WITHOUT LIMITATION, ALL IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. IN NO EVENT SHALL CROWDSTRIKE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE TOOLS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''
import hashlib
import os
import base64
import time
import datetime
import requests
import json
import threading
import traceback
import signal
import urllib
import socket
import logging    

logging.basicConfig(filename='crowdstrike-chronicle-client-logs.log', encoding='utf-8', level=logging.DEBUG)

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
        signal.signal(signal.SIGINT, signal_handler)
        print('ctrl+c to quit')
        # call main function
        self.main()
    
    def get_streams(self):
        try:
            # init
            appId = "ChronicleClient"
            discoverURL = "https://api.crowdstrike.com:443/sensors/entities/datafeed/v2?appId=" + appId
            headers = {'Authorization': 'bearer ' + self.token, 'Accept': 'application/json'}
            # parse response
            r = requests.get(discoverURL, headers=headers)
            # log api errors to chronicle
            if (int(r.status_code)>=400): 
                self.log_CS_error_to_chronicle(r.json())
            response = r.json()
            return response
        except:
            self.handle_exit(1, "unable to discover streams")

    def handle_exit(self, code, message):
        if (code == 1):
            logging.error(message)
        if (self.streamsStarted):
            try:
                with open('offset.json', 'w') as f:
                    json.dump(self.offsets, f)
            except:
                logging.error("offset.json not found")
        os._exit(code)

    def log_detection_to_chronicle_udm(self, obj):
        try:      
            headers = {'Content-Type':'application/json'}
            payload = {"events":[self.map_detection_to_udm(obj)]}
            r = requests.request("POST", "https://malachiteingestion-pa.googleapis.com/v1/udmevents?key=" + self.googleSecKey, data = json.dumps(payload), headers=headers)
            if (r.status_code>=400):
                logging.error("error logging to chronicle: " + r.text)
        except:
            self.handle_exit(1, "unable to write to chronicle")

    def log_CS_error_to_chronicle(self, response):
        try:      
            headers = {'Content-Type':'application/json'}
            errorLog = self.map_error_to_udm(response)
            payload = {"events":[errorLog]}
            r = requests.request("POST", "https://malachiteingestion-pa.googleapis.com/v1/udmevents?key=" + self.googleSecKey, data = json.dumps(payload), headers=headers)
            if (r.status_code>=400):
                logging.error("error logging to chronicle: " + r.text)
        except:
            self.handle_exit(1, "unable to write to chronicle")

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
                threads.append(threading.Thread(target=self.stream, args=(data_url, token, offset, refreshURL)))
                threads[-1].start()
                time.sleep(1)
            for t in threads:
                # join threads
                t.join()
        except:
            self.handle_exit(1, "failed to get stream token")

    def map_detection_to_udm(self, detectionEvent):
        timestampComponents = str(datetime.datetime.fromtimestamp(detectionEvent["event"]["ProcessStartTime"])).split()
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
        timestampComponents = str(datetime.datetime.fromtimestamp(int(time.time()))).split()
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
                    "hostname": socket.gethostname(),
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
            with open("offset.json") as json_file:
                self.offsets = json.load(json_file)
        except :
            logging.error("no offset file found")

    def parse_url(self, url):
        try:
            cid = url.split("_")[-1]
            segments = url.split("/")
            relevantURL = ""
            for i in range (3, len(segments)):
                relevantURL += "/" + segments[i]
            parsedRelevantURL = urllib.parse.quote(relevantURL, safe='')
            finalURL = segments[0]+"/"+segments[1]+"/"+segments[2]+"/api2/link?"+cid+"&url="+parsedRelevantURL
            return finalURL.split("_")[0]
        except: 
            return url

    def refresh_stream(self, refreshURL):
        try:
            # send refresh request
            headers = { 'Authorization': 'bearer %s' % self.token, 'Accept': 'application/json', 'Content-Type': 'application/json' }
            payload = { 'action_name': 'refresh_active_stream_session', 'appId': 'my_app_id' }
            r = requests.request("POST", refreshURL, data = payload, headers=headers)
            # log api errors to chronicle
            if (int(r.status_code)>=400): 
                self.log_CS_error_to_chronicle(r.json())
        except:
            self.handle_exit(1, "failed to refresh stream")

    def refresh_token(self):
        try:
            # init 
            url = 'https://api.crowdstrike.com/oauth2/token'
            payload = 'client_id='+self.clientId+'&client_secret='+self.clientSecret
            tokenHeaders = {'content-type': 'application/x-www-form-urlencoded'}
            # parse response
            r = requests.request("POST", url, data=payload, headers=tokenHeaders)
            # log api errors to chronicle
            if (int(r.status_code)>=400): 
                self.log_CS_error_to_chronicle(r.json())
            r = r.json()
            token = r['access_token']
            self.token = token
            # set token period start time
            self.token_period_start = time.time()
        except:
            self.handle_exit(1, "unable to get token")

    def stream(self, url, token, offset, refreshURL):
        # @param url: the stream url
        # @param token: the stream token
        # @param offset: the offset to begin at
        # @param refreshURL: the url to refresh the stream
        try:
            # connect to stream url
            stream_period_start = time.time()
            requrl = url + "&offset=%s" %offset
            headers={'Authorization': 'Token %s' % token, 'Connection': 'Keep-Alive'}
            r = requests.get(requrl, headers=headers, stream=True)
            self.streamsStarted = True
            for line in r.iter_lines():
                # check new streams
                if line:
                    decoded_line = line.decode('utf-8')
                    decoded_line = json.loads(decoded_line)
                    self.offsets[url] = decoded_line['metadata']['offset']
                    # log to detections to chronicle
                    if (decoded_line['metadata']['eventType'] == "DetectionSummaryEvent"):
                        self.log_detection_to_chronicle_udm(decoded_line)
                # refresh stream after 25 minutes
                if (time.time() - stream_period_start >= 1500):
                    stream_period_start = time.time()
                    self.refresh_stream(refreshURL)
                # refresh token after 25 minutes
                if (time.time() - self.token_period_start >= 1500):
                    self.refresh_token()
        except: 
            self.handle_exit(1, "error reading last stream chunk")

# start Chronicle Client class
ChronicleClient()