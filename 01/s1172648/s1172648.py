#!/usr/bin/env python3

from sys import argv, exit

from json import loads

from urllib.parse import urlparse

from tld import get_fld
from tld.exceptions import TldBadUrl


####################
##  Input/Output  ##
####################

def analyze_har(path):
    try:
        with open(path, 'r') as har_file:
            har_text = har_file.read()
        with open('domain_map.json', 'r') as domain_map_file:
            domain_map_text = domain_map_file.read()
    except OSError as e:
        print(f'Failed to read file: {e}')
        exit(1)

    log = loads(har_text)['log']
    domain_map = loads(domain_map_text)

    results = collect_results(log, domain_map)

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

def collect_results(log, domain_map):
    results = dict()

    num_reqs(log, results)
    num_responses(log, results)
    num_redirections(log, results)
    num_cross_origin_redirections(log, results)
    num_requests_w_cookies(log, results)
    num_responses_w_cookies(log, results)
    third_party_domains(log, results)
    potential_tracking_cookies(log, results)
    third_party_entities(log, results, domain_map)
    non_get_request_origins(log, results)

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
    first_party_domain = get_first_party_domain(log)
    third_party_domains = set()

    for entry in log['entries']:
        if has_response(entry):
            third_party_domains.add(get_fld(entry['request']['url']))

    third_party_domains.discard(first_party_domain)

    results['third_party_domains'] = [domain for domain in third_party_domains]


def potential_tracking_cookies(log, results):
    cookies = set()

    for entry in log['entries']:
        for value in get_header_values(entry['response']['headers'], 'set-cookie'):
            request_domain = get_fld(entry['request']['url'])

            cookies.add(parse_potential_tracking_cookie(value, request_domain))

    cookies.discard(None)

    results['potential_tracking_cookies'] = [cookie for cookie in cookies]


def third_party_entities(log, results, domain_map):
    first_party_domain = get_first_party_domain(log)
    display_names = set()

    for entry in log['entries']:
        request_domain = get_fld(entry['request']['url'])
        if request_domain != first_party_domain and request_domain in domain_map:
            display_names.add(domain_map[request_domain]['displayName'])

    results['third_party_entities'] = [display_name for display_name
        in display_names]


def non_get_request_origins(log, results):
    non_get_origins = set()

    for entry in log['entries']:
        if entry['request']['method'].upper() != 'GET':
            url = urlparse(entry['request']['url'])
            non_get_origins.add((url.scheme, assume_port(url.scheme),
                url.hostname))

    results['non_get_request_origins'] = [origin for origin
        in non_get_origins]


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


def get_header_values(headers, name):
    values = []

    for header in headers:
        if header['name'].lower() == name.lower():
            values.append(header['value'])

    return values


def get_first_party_domain(log):
    return get_fld(log['pages'][0]['title'])


def assume_port(protocol):
    if protocol.upper() == 'HTTPS':
        return 443
    if protocol.upper() == 'HTTP':
        return 80

    assert False


# Returns None when the cookie does not have SameSite=None.
def parse_potential_tracking_cookie(value, request_domain):
        name_value, attributes = value.split(';', 1)
        name, value = name_value.split('=', 1)

        if 'SameSite=None' not in attributes:
            return None

        return (name, value, request_domain)


if __name__ == '__main__':
    main()
