#!/usr/bin/env python3

from sys import argv, exit

from json import loads

from tld import get_fld
from tld.exceptions import TldBadUrl


####################
##  Input/Output  ##
####################

def analyze_har(path):
    try:
        with open(path, 'r') as file:
            har = file.read()
    except OSError as e:
        print(f'Failed to read file: {e}')
        exit(1)

    log = loads(har)['log']

    results = collect_results(log)

    return results


def main():
    if len(argv) != 2:
        print(f'Usage: {argv[0]} <HAR path>')
        exit(1)

    results = analyze_har(argv[1])

    print(results)


##########################
##  Results Dictionary  ##
##########################

def collect_results(log):
    results = dict()

    num_reqs(log, results)
    num_responses(log, results)
    num_redirections(log, results)
    num_cross_origin_redirections(log, results)
    num_requests_w_cookies(log, results)
    num_responses_w_cookies(log, results)
    third_party_domains(log, results)

    return results


def num_reqs(log, results):
    results['num_reqs'] = len(log['entries'])


def num_responses(log, results):
    results['num_responses'] = len([entry for entry in log['entries']
        if has_response(entry)])


def num_redirections(log, results):
    results['num_redirections'] = len([entry for entry in log['entries']
        if is_redirection(entry)])


def num_cross_origin_redirections(log, results):
    results['num_cross_origin_redirections'] = 0

    for entry in log['entries']:
        if is_redirection(entry):
            try:
                if (get_fld(entry['response']['redirectURL'])
                        != get_fld(entry['request']['url'])):
                    results['num_cross_origin_redirections'] += 1
            # Treat url parsing error as no cross origin redirection.
            except TldBadUrl:
                pass


def num_requests_w_cookies(log, results):
    results['num_requests_w_cookies'] = len([entry for entry in log['entries']
        if get_header_value(entry['request']['headers'], 'cookie') is not None])


def num_responses_w_cookies(log, results):
    results['num_responses_w_cookies'] = len([entry for entry in log['entries']
        if get_header_value(entry['response']['headers'], 'set-cookie') is not None])


def third_party_domains(log, results):
    first_party_domain = get_fld(log['pages'][0]['title'])
    third_party_domains = set()

    for entry in log['entries']:
        if has_response(entry):
            third_party_domains.add(get_fld(entry['request']['url']))

    third_party_domains.discard(first_party_domain)

    results['third_party_domains'] = [domain for domain in third_party_domains]


#########################
##  Utility Functions  ##
#########################

def has_response(entry):
    # Status equal to 0 indicates error to receive response.
    return entry['response']['status'] != 0


def is_redirection(entry):
    return 300 <= entry['response']['status'] < 400


def get_header_value(headers, name):
    for header in headers:
        if header['name'].lower() == name.lower():
            return header['value']

    return None


if __name__ == '__main__':
    main()
