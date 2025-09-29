#!/usr/bin/env python3

from sys import argv, exit

from json import loads

def analyze_har(path):
    try:
        with open(path, 'r') as file:
            contents = file.read()
    except Exception as e:
        print(f'Failed to read file: {e}')
        exit(1)

    har = loads(contents)
    print(har)

def main():
    if len(argv) != 2:
        print(f'Usage: {argv[0]} <HAR path>')
        exit(1)

    analyze_har(argv[1])


if __name__ == '__main__':
    main()
