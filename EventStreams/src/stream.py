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

class Stream():
    def __init__(self):
        # default offset to high value to get all streams
        self.default_offset = 999999999 
        self.offsets = dict()
        self.streamsStarted = False
        # get client credentials
        try:
            # assumes that clientId is on line 1 and clientSecret is on line 2
            with open("credentials.txt") as f:
                self.clientId = f.readline().strip('\n')
                self.clientSecret = f.readline()
        except: 
            self.handle_exit(1, "credentials.txt not found")
        # get chronicle credentials
        try:
            with open("googlesecuritykey.txt") as f:
                self.googleSecKey = f.readline()
        except: 
            self.handle_exit(1, "googlesecuritykey.txt not found")
        # assign payload, urls, and headers
        self.payload = 'client_id='+self.clientId+'&client_secret='+self.clientSecret
        self.url = 'https://api.crowdstrike.com/oauth2/token'
        self.headers = {'content-type': 'application/x-www-form-urlencoded'}
        self.appId = "ChronicleClient"
        self.discoverURL = "https://api.crowdstrike.com:443/sensors/entities/datafeed/v2?appId=" + self.appId
        # get token
        self.refreshToken()
        # define signal interrupt code
        def signal_handler(sig, frame):
            self.handle_exit(0, "exiting...")
        signal.signal(signal.SIGINT, signal_handler)
        print('ctrl+c to quit')
        # call main function
        self.main()

    def refreshToken(self):
        try:
            # send request
            response = requests.request("POST", self.url, data=self.payload, headers=self.headers)
            # parse response
            r = response.json()
            token = r['access_token']
            self.token = token
            # set token period start time
            self.token_period_start = time.time()
        except:
            self.handle_exit(1, "unable to get token")

    def main(self):
        # read offset from file
        try:
            with open("offset.json") as json_file:
                self.offsets = json.load(json_file)
        except :
            print("no offset file found")
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
                print("event occurance completed")
        except:
            self.handle_exit(1, "failed to get stream token")

    def get_streams(self):
        try:
            # parse response
            headers = {'Authorization': 'bearer ' + self.token, 'Accept': 'application/json'}
            r = requests.get(self.discoverURL, headers=headers)
            response = r.json()
            return response
        except:
            self.handle_exit(1, "unable to discover streams")

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
            print("streaming API connection established")
            self.streamsStarted = True
            for line in r.iter_lines():
                # print any new streams
                if line:
                    decoded_line = line.decode('utf-8')
                    decoded_line = json.loads(decoded_line)
                    self.offsets[url] = decoded_line['metadata']['offset']
                    # log to chronicle
                    try:
                        headers = {'Content-Type':'application/json'}
                        payload = {"log_type":"BIND_DNS","entries":[{"log_text":json.dumps(decoded_line)}]}
                        response = requests.request("POST", "https://malachiteingestion-pa.googleapis.com/v1/unstructuredlogentries?key=" + self.googleSecKey, data = json.dumps(payload), headers=headers)
                        print("chronicle log code: %s" %(response.status_code))
                    except:
                        self.handle_exit(1, "unable to write to chronicle")
                # refresh stream after 25 minutes
                if (time.time() - stream_period_start >= 1500):
                    try:
                        # send refresh request
                        headers = { 'Authorization': 'bearer %s' % self.token, 'Accept': 'application/json', 'Content-Type': 'application/json' }
                        payload = { 'action_name': 'refresh_active_stream_session', 'appId': 'my_app_id' }
                        response = requests.request("POST", refreshURL, data = payload, headers=headers)
                        print("stream refresh code: %s" %(response.status_code))
                        stream_period_start = time.time()
                    except:
                        self.handle_exit(1, "failed to refresh stream")
                # refresh token after 25 minutes
                if (time.time() - self.token_period_start >= 1500):
                    self.refreshToken()
        except: 
            self.handle_exit(1, "error reading last stream chunk")

    def handle_exit(self, code, message):
        print(message)
        if (self.streamsStarted):
            try:
                with open('offset.json', 'w') as f:
                    json.dump(self.offsets, f)
            except:
                print("offset.json not found")
        os._exit(code)

# start stream class
Stream()






