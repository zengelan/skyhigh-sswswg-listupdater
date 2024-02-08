#!/usr/bin/env python3
import csv
import os
from datetime import datetime
import requests
import json

def pretty(in_obj):
    if not in_obj:
        return "<Nothing>"
    return str(json.dumps(in_obj, indent=2, sort_keys=True, default=str))


class MvcConnection:
    session = None
    tenants = None
    username = None
    password = None
    bps_tenantid = None
    env = None
    lastauthdate = None
    token_lifetime = None
    iam_token = None
    tenantid = None
    authinfo = None
    mpops = None
    iam_user_details = None
    CSPID_AWS = 2049

    def __init__(self, username, password, bps_tenantid=None, env="www.myshn.net"):
        self.username = username
        self.password = password
        self.bps_tenantid = bps_tenantid
        self.env = "https://" + env
        self.session = requests.session()

    @property
    def bps_tenantid_web(self):
        # a special version of the bpsid for the web policy, lowercase and with underscore instead of dashes
        if self.bps_tenantid:
            return self.bps_tenantid.lower().replace('-', '_')
        return None

    def authenticate(self, bps_tenantid=None):
        if not self.bps_tenantid and not bps_tenantid:
            raise (
                "Error, can't authenticate unless you supply a tenant id from this list: {}".format(self.get_tenants()))
        if bps_tenantid and not self.bps_tenantid:
            self.bps_tenantid = bps_tenantid
        # 1. Get IAM token
        iam_url = "https://iam.mcafee-cloud.com/iam/v1.1/token"  # hard coded
        payload = {
            "client_id": "0oae8q9q2y0IZOYUm0h7",  # hard coded
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
            "scope": "shn.con.r web.adm.x web.rpt.x web.rpt.r web.lst.x web.plc.x web.xprt.x web.cnf.x uam:admin",
            "tenant_id": self.bps_tenantid
        }
        res = self.session.post(iam_url, data=payload)  # handling directly here

        if res.status_code != 200:
            print("Could not get IAM token: " + res.text)
            raise RuntimeError("Exception, can't authenticate")
        self.iam_token = res.json().get("access_token")
        # 2. Get MVISION Cloud tokens
        #    Now we can use the IAM token to get our session tokens for MVISION Cloud
        url = self.env + "/neo/neo-auth-service/oauth/token?grant_type=iam_token"
        heads = {'x-iam-token': self.iam_token}
        r = self.session.post(url, headers=heads)
        if r.status_code != 200:
            print("Could not authenticate to MVISION Cloud: " + res.text)
            raise RuntimeError("Exception, can't authenticate")
        self.lastauthdate = datetime.now()
        mvc_authinfo = r.json()
        self.tenantid = int(mvc_authinfo.get("tenantID"))
        self.authinfo = {
            'x-access-token': mvc_authinfo.get("access_token"),
            'x-refresh-token': mvc_authinfo.get("refresh_token"),
            'tenant-id': int(self.tenantid),
            'tenant-name': str(mvc_authinfo.get('tenantName')),
            'user-id': int(mvc_authinfo.get("userId")),
            'user-email': str(mvc_authinfo.get("email")),
            'user-name': str(mvc_authinfo.get("user")),
        }
        self.token_lifetime = mvc_authinfo.get("expires_in")
        session_headers = {'x-access-token': mvc_authinfo.get("access_token"),
                           'x-refresh-token': mvc_authinfo.get("refresh_token")}
        self.session.headers.update(session_headers)
        # print("Authenticated successfully")
        return True

    def get_tenants(self):
        print(self.username)
        
        if not self.tenants:
            # we handle this one direct as its so special
            url = self.env + "/shnapi/rest/external/api/v1/groups?source=shn.ec.x"
            res = self.session.get(url, auth=(self.username, self.password))
           
            if res.status_code != 200:
                raise PermissionError("Could not get associated tenants", res)
            self.tenants = res.json()
        return self.tenants

    def comm_web(self, method, url, jsondata=None, rawresponse=False):
        if self.needs_new_auth():
            self.authenticate()
        url = url.replace("##CID##", "customer_{}".format(self.bps_tenantid_web))
        url = "https://webpolicy.cloud.mvision.mcafee.com/api{}".format(url)
        webheaders = self.session.headers.copy()
        webheaders.update({"Authorization": "Bearer {}".format(self.iam_token)})
        try:
            res = self.session.request(method, url, json=jsondata, headers=webheaders)
        except requests.exceptions.ConnectionError as e:
            print("   ConnectionError during comm to url '{}', trying again".format(url), e)
            res = self.session.request(method, url, json=jsondata, headers=webheaders)
        if rawresponse:
            return res
        if res.status_code != 200:
            return {"error": res.text, "status_code": res.status_code}
        return res.json()

    def needs_new_auth(self):
        if not self.lastauthdate:
            return True
        since = datetime.now() - self.lastauthdate
        if since.total_seconds() >= self.token_lifetime:
            return True
        else:
            return False

    def web_policy_lists_customer(self):
        url = "/policy/v1/gps/content/product/Web/Policy/##CID##/Policy/lists"
        res = self.comm_web("GET", url)
        return res

    def web_policy_list_by_id(self, list_id):
        url = "/policy/v1/gps/content/product/Web/Policy/##CID##/Policy/{}".format(list_id)
        res = self.comm_web("GET", url, rawresponse=True)
        if not res.status_code == 200:
            raise BaseException("Could not get list detail",res)
        list = res.json()
        list.update({"hash": res.headers.get("ETag")})
        return list

    def web_policy_replace_entries(self, list_id, entries):
        if not isinstance(entries, list) or not isinstance(entries[0], dict) or not entries[0].get("value"):
            raise BaseException("entry must be a list of dicts with at least the field 'value'. Field 'comment' is optional")

        # get current list:
        current = self.web_policy_list_by_id(list_id)

        # 1. create a copy
        newlist = current.copy()
        # 2 remove the hash code
        del (newlist["hash"])
        # 3 set the type if needed:
        if not newlist.get("type"):
            # we also need to figure out the type reliably
            lists = self.web_policy_lists_customer()
            for l in lists:
                if l["id"] == current["id"]:
                    newlist["type"] = l["type"]
                    break
        # 4 replace the entries
        newlist["entries"]=entries
        # 5 set list type
        if not newlist.get("listFeature"):
            newlist["listFeature"] = "User defined"

        data = [{"op": "lists.single.update",
                 "name": current.get("name"),
                 "path": "/{}".format(current.get("id")),
                 "absolute": False,
                 "content": newlist,
                 "hash": current.get("hash")}]
        url = "/policy/v1/commit"
        res = self.comm_web("POST", url, jsondata=data, rawresponse=True)
        if not res.status_code == 200:
            raise BaseException("Didn't get a 200 for the commit", res)
        response = res.json()
        return response["hashes"]["/" + current.get("id")]

    def web_policy_list_add_entry(self, list_id, entry):
        if not isinstance(entry, dict) or not entry.get("value"):
            raise BaseException("entry must be a dict with at least the filed 'value'. Field 'comment' is optional")
        if not entry.get("comment"):
            entry["comment"] = ""
        # get current list:
        current = self.web_policy_list_by_id(list_id)

        # 1. create a copy
        newlist = current.copy()
        # 2 remove the hash code
        del (newlist["hash"])
        # 3 set the type if needed:
        if not newlist.get("type"):
            # we also need to figure out the type reliably
            lists = self.web_policy_lists_customer()
            for l in lists:
                if l["id"] == current["id"]:
                    newlist["type"] = l["type"]
                    break
        # 4 append the new value
        newlist["entries"].append(entry)
        # 5 append the new value
        if not newlist.get("listFeature"):
            newlist["listFeature"] = "User defined"

        data = [{"op": "lists.single.update",
                 "name": current.get("name"),
                 "path": "/{}".format(current.get("id")),
                 "absolute": False,
                 "content": newlist,
                 "hash": current.get("hash")}]
        url = "/policy/v1/commit"
        res = self.comm_web("POST", url, jsondata=data, rawresponse=True)
        if not res.status_code == 200:
            raise BaseException("Didn't get a 200 for the commit", res)
        response = res.json()
        return response["hashes"]["/" + current.get("id")]


def read_text_file(filename):
    entries = []
    try:
        with open(filename, 'r' ) as theFile:
            reader = csv.DictReader(theFile,delimiter=';', quotechar='"')
            for line in reader:
                entries.append(line)
    except Exception as e:
        print("Could not read csv file from {}".format(filename), e)
    return entries


if __name__ == '__main__':
    # Enter script configuration data below
    list_name=""
    text_file=""
    username = ""
    password = ""
    tenantid = ""
    # Enter script configuration data above



    mvcc = MvcConnection(username=username, password=password)
    print("Getting tenant list for user")
    tenants = mvcc.get_tenants()
    print("Tenant list is : {}".format(tenants))
    mvcc.bps_tenantid=tenantid
    print("Authenticating ...")
    if not mvcc.authenticate():
        print("Could not authenticate")
        exit(1)
    print("Logged into tenant")
    # read text file
    textfile_entries = read_text_file(text_file)
    now = datetime.utcnow()
    customer_lists = mvcc.web_policy_lists_customer()
    print("Found {} customer managed lists".format(len(customer_lists)))
    for l in customer_lists:
        if l["name"] == list_name:
            list_id = l["id"]
    print("The list with name '{}' has ID '{}'".format(list_name, list_id))
    my_list = mvcc.web_policy_list_by_id(list_id)
    print("{} entries in list '{}': \n{}".format(len(my_list["entries"]),list_name,pretty(my_list["entries"])))
    print("Now replacing with list: {}".format(textfile_entries))
    res = mvcc.web_policy_replace_entries(list_id,textfile_entries)
    my_new_list = mvcc.web_policy_list_by_id(list_id)
    print("Now we have {} entries in list '{}': \n{}".format(len(my_new_list["entries"]),list_name,pretty(my_new_list["entries"])))
    print("Done")
    exit(0)