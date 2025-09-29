#!/usr/bin/env python3

from sys import argv, exit

from json import loads

from tld import get_fld


def num_reqs(log, results):
    results['num_reqs'] = len(log['entries'])


def num_responses(log, results):
    # Status equal to 0 indicates error to receive response.
    results['num_responses'] = len([entry for entry in log['entries']
        if entry['response']['status'] != 0])


def is_redirection(entry):
    return 300 <= entry['response']['status'] < 400


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
            except:
                pass


def get_header_value(headers, name):
    for header in headers:
        if header['name'].lower() == name.lower():
            return header['value']

    return None


def num_requests_w_cookies(log, results):
    results['num_requests_w_cookies'] = len([entry for entry in log['entries']
        if get_header_value(entry['request']['headers'], 'cookie') is not None])


def num_responses_w_cookies(log, results):
    results['num_responses_w_cookies'] = len([entry for entry in log['entries']
        if get_header_value(entry['response']['headers'], 'set-cookie') is not None])


def collect_results(log):
    results = dict()

    num_reqs(log, results)
    num_responses(log, results)
    num_redirections(log, results)
    num_cross_origin_redirections(log, results)
    num_requests_w_cookies(log, results)
    num_responses_w_cookies(log, results)

    return results


def analyze_har(path):
    try:
        with open(path, 'r') as file:
            har = file.read()
    except Exception as e:
        print(f'Failed to read file: {e}')
        exit(1)

    log = loads(har)['log']
    #print(log['entries'][0].keys())

    results = collect_results(log)

    return results

def main():
    if len(argv) != 2:
        print(f'Usage: {argv[0]} <HAR path>')
        exit(1)

    results = analyze_har(argv[1])

    print(results)


if __name__ == '__main__':
    main()
