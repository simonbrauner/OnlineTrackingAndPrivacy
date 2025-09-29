#!/usr/bin/env python3

from sys import argv, exit

from json import loads


def num_reqs(log, results):
    results['num_reqs'] = len(log['entries'])


def num_responses(log, results):
    # Status equal to 0 indicates error to receive response.
    results['num_responses'] = len([x for x in log['entries'] if x['response']['status'] != 0])


def collect_results(log):
    results = dict()

    num_reqs(log, results)
    num_responses(log, results)

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
