#!/usr/bin/env python3

from sys import argv, exit

def analyze_har(path):
    print(f'TODO: {path}')


def main():
    if len(argv) != 2:
        print(f'Usage: {argv[0]} <HAR path>')
        exit(1)

    analyze_har(argv[1])


if __name__ == '__main__':
    main()
