#!/usr/bin/env python3

from sys import argv, exit, stderr

from json import loads, dump

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
        print(f'Failed to read file: {e}', file=stderr)
        exit(1)

    log = loads(har_text)['log']
    domain_map = loads(domain_map_text)

    results = collect_results(log, domain_map)

    return results


def write_jsons(paths):
    all_results = []

    for path in paths:
        current_results = analyze_har(path)
        all_results.append(current_results)

        with open(get_json_path(path), 'w') as file:
            dump(current_results, file, indent=4)

    combined_results = combine_results(all_results)

    with open('combined.json', 'w') as file:
        dump(combined_results, file, indent=4)


def main():
    if len(argv) == 1:
        path1 = 'universiteitleiden.nl.har'
        path2 = 'uva.nl.har'
    elif (len(argv) == 3 and is_har_path(argv[1])
            and is_har_path(argv[2])):
        path1 = argv[1]
        path2 = argv[2]
    else:
        print(f'Usage: {argv[0]} [path1.har path2.har]', file=stderr)
        exit(1)

    write_jsons([path1, path2])


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

    results['third_party_domains'] = set_to_list(third_party_domains)


def potential_tracking_cookies(log, results):
    cookies = set()

    for entry in log['entries']:
        for value in get_header_values(entry['response']['headers'], 'set-cookie'):
            request_domain = get_fld(entry['request']['url'])

            cookies.add(parse_potential_tracking_cookie(value, request_domain))

    cookies.discard(None)

    results['potential_tracking_cookies'] = set_to_list(cookies)


def third_party_entities(log, results, domain_map):
    first_party_domain = get_first_party_domain(log)
    display_names = set()

    for entry in log['entries']:
        request_domain = get_fld(entry['request']['url'])
        if request_domain != first_party_domain and request_domain in domain_map:
            display_names.add(domain_map[request_domain]['displayName'])

    results['third_party_entities'] = set_to_list(display_names)


def non_get_request_origins(log, results):
    non_get_origins = set()

    for entry in log['entries']:
        if entry['request']['method'].upper() != 'GET':
            url = urlparse(entry['request']['url'])
            non_get_origins.add((url.scheme, assume_port(url.scheme),
                url.hostname))

    results['non_get_request_origins'] = set_to_list(non_get_origins)


###################################
##  Combined Results Dictionary  ##
###################################

def combine_results(all_results):
    combined_results = dict()

    combine_field(all_results, combined_results,
        'third_party_domains', 'common_third_party_domains')
    combine_field(all_results, combined_results,
        'third_party_entities', 'common_third_party_entities')
    combine_field(all_results, combined_results,
        'potential_tracking_cookies', 'common_cookies')

    return combined_results


def combine_field(all_results, combined_results,
        input_field_name, output_field_name):
    field_values = list_to_set(all_results[0][input_field_name])

    for remaining_results in all_results:
        field_values &= list_to_set(remaining_results[input_field_name])

    combined_results[output_field_name] = set_to_list(field_values)


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


def is_har_path(path):
    return path.endswith('.har')


def get_json_path(har_path):
    return har_path[:-len('har')] + 'json'


def list_to_set(list_to_convert):
    return {value for value in list_to_convert}


def set_to_list(set_to_convert):
    # Sort to make the results reproducible.
    return list(sorted(set_to_convert))


# Returns None when the cookie does not have SameSite=None.
def parse_potential_tracking_cookie(value, request_domain):
        name_value, attributes = value.split(';', 1)
        name, value = name_value.split('=', 1)

        if 'SameSite=None' not in attributes:
            return None

        return (name, value, request_domain)


if __name__ == '__main__':
    main()
