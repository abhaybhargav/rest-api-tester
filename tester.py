from requests import Request, Session, Response
import logging
from datetime import datetime
import yaml
LOG_FILENAME = 'test.log'
import sys
import json
import unicodedata

glovars = {}

#need to be changed from hardcoded values to config values.
proxies = {'http': 'http://localhost:8090', 'https': 'https://localhost:8090'}
cert_bundle = '/path/to/owasp_zap_root_ca.cer'
#cert_bundle = '/Users/abhaybhargav/Documents/burp-ca.der'


logging.basicConfig(filename=LOG_FILENAME, level = logging.DEBUG)

def pr(message):
    print "[+] {0}".format(message)
#
# def get_headers(headerlist):
#     all_headers = {}
#     for header in headerlist:
#         for k,v in header.items():
#             all_headers[k] = v
#
#     return all_headers

# def make_request(uri, method, headers, data = None, params = None):
#     print "[+] Making Request"
#     rsess = Session()
#     req = Request(method, url=uri, headers = headers, data = data)
#     prepped = req.prepare()
#     if 'User-Agent' in prepped.headers.keys():
#         del prepped.headers['User-Agent']
#     if 'Connection' in prepped.headers.keys():
#         del prepped.headers['Connection']
#     print prepped.headers
#     response = rsess.send(prepped, verify = cert_bundle, proxies = proxies)
#     #response = requests.post(url = uri, headers = headers, data=data, proxies = proxies, verify = cert_bundle)
#     print "Status Code from make_request(): {0}".format(response.status_code)
#     print "Content from make_request(): {0}".format(response.text)


#    return response

# # TODO: The check_keys() function is used when you need to validate keys. Its not used currently.
def check_keys(mydict, keylist, varkeys = None):
    if isinstance(mydict, dict):
#        keylist = []
        #vardict = {}
        keylist += mydict.keys()
        #print "[D]---- varkeys: {0}".format(varkeys)
        if varkeys:
            for var in varkeys:
                var_key_val = var['name']
                if var_key_val in mydict.keys():
                    full_var_name = ""
                    if var['prefix'] and var['suffix']:
                        full_var_name = "{0}{1}{2}".format(var['prefix'], mydict[var_key_val], var['suffix'])
                    elif var['prefix']:
                        full_var_name = "{0}{1}".format(var['prefix'], mydict[var_key_val])
                    elif var['suffix']:
                        full_var_name = "{0}{1}".format(mydict[var_key_val], var['suffix'])
                    else:
                        full_var_name = mydict[var_key_val]

                    glovars[var_key_val] = full_var_name
                    #print "[D]---- glovars: {0}".format(glovars)
            map(lambda x: check_keys(x, keylist), mydict.values())
        else:
            map(lambda x: check_keys(x, keylist), mydict.values())
    elif isinstance(mydict,list):
        map(lambda x: check_keys(x, keylist), mydict)

    return keylist


def process_var_headers(header_list):
    var_headers = {}
    if header_list:
        for header in header_list:
            if header['type'] == 'var_key':
                named_header = header['name']
                var_header = header['varname']
                if var_header in glovars.keys():
                    var_headers[named_header] = glovars[var_header]
    return var_headers


def process_static_headers(header_list):
    static_headers = {}
    if header_list:
        for header in header_list:
            if header['type'] == 'static':
                name_header = header['name']
                val_header = header['value']
                static_headers[name_header] = val_header
    return static_headers


def are_lists_same(response_json, yaml_json):
    return set(response_json) == set(yaml_json)

def process_response(response, req):
    #resp = Response(response)
    #expected_response
    if response.status_code == req['request']['response']['status']:
        print "\t--- [+] Response Status Code: {0}".format(response.status_code)
        if 'Content-Type' in response.headers.keys():
            if response.headers['Content-Type'] == req['request']['response']['content_type']:
                print "\t ---[+] Response Content Type: {0}".format(response.headers['Content-Type'])
                if 'json' in req['request']['response']['content_type']:
#                    if len(response.json()) == len(req['request']['response']['json']):
                    if 'var_key' in req['request']['response'].keys():
                        varlist = req['request']['response']['var_key']
                        #print "[D]---- varlist: {0}".format(varlist)
                        all_test_keys = check_keys(req['request']['response']['json'], [])
                        response_keys = check_keys(response.json(), [], varlist)
                        response_keys = [items.encode('UTF8') for items in list(set(response_keys))]
                        if are_lists_same(all_test_keys, response_keys):
                            print "\t --- all_test_keys: {0}".format(all_test_keys)
                            print "\t--- response_keys: {0}".format(response_keys)
                    else:
                        all_test_keys = check_keys(req['request']['response']['json'], [])
                        response_keys = check_keys(response.json(), [])
                        #if list(set(all_test_keys)) == list(set(response_keys)):
                        response_keys = [items.encode('UTF8') for items in list(set(response_keys))]
                        if are_lists_same(all_test_keys, response_keys):
                            print "\t --- all_test_keys: {0}".format(all_test_keys)
                            print "\t--- response_keys: {0}".format(response_keys)
                        #    pass






                                # print "Var Name: {0}, Response Var: {1}".format(name, response.json()[name])
                                # if vars['prefix'] and vars['suffix']:
                                #     glovars[name] = "{0}{1}{2}".format(vars['prefix'], response.json()[name], vars['suffix'])
                                # elif vars['prefix']:
                                #     glovars[name] = "{0}{1}".format(vars['prefix'], response.json()[name])
                                # elif vars['suffix']:
                                #     glovars[name] = "{0}{1}".format(response.json()[name], vars['suffix'])
                                # else:
                                #     glovars[name] = response.json()[name]



def process_request(req):
    # api_stream = open(file, 'r')
    # api = yaml.load_all(api_stream)
    # for reqs in api:
    #     for req in reqs:
    preq = Request()
    pr("Testing: {0}, which is a {1} request".format(req['request']['name'], req['request']['method']))
    static_headers = process_static_headers(req['request']['headers'])
    var_headers = process_var_headers(req['request']['headers'])
    all_headers = dict(static_headers.items() + var_headers.items())
    #print all_headers
    if req['request']['params']:
        preq.params = req['request']['params']
    preq.headers = all_headers
    preq.method = req['request']['method']
    preq.url = req['request']['uri']
    if 'body' in req['request'].keys():
        if req['request']['body']['type'] == 'post-vars':
            preq.data = req['request']['body']['value']
        elif req['request']['body']['type'] == 'json':
            preq.json = req['request']['body']['value']
        elif req['request']['body']['type'] == 'file':
            filepath = req['request']['body']['value']['filepath']
            preq.files = {filepath: open(filepath, 'rb')}
        else:
            raise Exception('Payload type unsupported')
            sys.exit(1)

    rsess = Session()
    prepped = preq.prepare()
    # for item in req['request']['exclude_headers']:
    #     if item in prepped.headers.keys():
    #         del prepped.headers[item]

    response = rsess.send(prepped, verify = cert_bundle, proxies = proxies)

    return response


            # headers =  get_headers(req['request']['headers'])
            # print "[+] Request headers: {0}".format(headers)
            # rmethod = req['request']['method']
            # print "[+] Request method: {0}".format(rmethod)
            # url = req['request']['uri']
            # print "[+] Request URI: {0}".format(url)
            # if req['request']['body']['type'] == 'post-vars':
            #     post_data = req['request']['body']['value']
            #     print "[+] Request Body Params: {0}".format(post_data)
            #
            # response = make_request(url, rmethod, headers, data = post_data)
            #
            # if response.status_code == req['request']['response']['status']:
            #     print "[+] Response Status Code: {0}".format(response.status_code)
            #     if response.headers['Content-Type'] == req['request']['response']['content_type']:
            #         print "[+] Response Content Type: {0}".format(response.headers['Content-Type'])
            #         if 'json' in req['request']['response']['content_type']:
            #             if len(response.json()) == len(req['request']['response']['json']):
            #                 print 'valid response'
            #                 for vars in req['request']['response']['var_key']:
            #                     glovars[vars] = response.json()[vars]



def main():
    # this will need to be CMD line param as well.
    api_stream = open('test_api.yml', 'r')
    api = yaml.load_all(api_stream)
    for reqs in api:
        for req in reqs:
            response = process_request(req)
            process_response(response, req)
#            print glovars


if __name__ == '__main__': main()