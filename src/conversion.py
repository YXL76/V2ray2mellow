#!/usr/bin/python
# -*- coding: UTF-8 -*-

import requests
from base64 import b64decode
from json import loads
from re import match
from string import Template

pointTemplate = {
    'tcp': Template('?network=tcp'),
    'kcp': Template('?network=kcp'),
    'ws': Template('?network=ws&ws.host=${host}'),
    'h2': Template('?network=http&http.host=${host}'),
    'quic': Template('?network=quic&quic.security=${security}&quic.key=${key}&header=none'),
    'vmess': Template('Proxy-${index}, vmess1, vmess1://${id}@${add}:${port}${path}'),
    'shadowsocks': Template('Proxy-${index}, ss, ss://${method}:${password}@${add}:${port}'),
    'socks': Template('Proxy-${index}, builtin, socks, address=${add}, port=${port}, user=${user}, pass=${password}')
}


def getV2ray(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36'
    }
    session = requests.Session()
    response = session.get(url=url, headers=headers)
    # print(response.text)
    if response.status_code == 200:
        v2ray = b64decode(response.text)
        v2ray = v2ray.splitlines()
        print('[INFO] request success')
    else:
        print('[ERROR] request fail')
    return v2ray


def decode(v2ray):
    protocol = []
    configuration = []
    for i in v2ray:
        _ = match('^(.+)://(.+)$', i.decode('utf-8'))
        if _:
            protocol.append(_.group(1))
            configuration.append(loads(b64decode(_.group(2))))
    print('[INFO] get v2ray url success')
    return protocol, configuration


def converter(protocol, configuration, index=1):
    for i in range(len(protocol)):
        _ = protocol[i]
        __ = configuration[i]
        point = ''

        if __['v'] != '2':
            continue

        if _ == 'vmess':
            point = pointTemplate['vmess'].substitute(
                index=str(index), id=__['id'], add=__['add'], port=__['port'], path=('/' + __['path']) if (__['path']) else '')

            net = __['net']
            if net == 'tcp':
                point += pointTemplate['tcp'].substitute()
            elif net == 'kcp':
                point += pointTemplate['kcp'].substitute()
            elif net == 'ws':
                point += pointTemplate['ws'].substitute(
                    host=__['host'] if (__['host']) else __['add'])
            elif net == 'h2':
                point += pointTemplate['h2'].substitute(
                    host=__['host'] if (__['host']) else __['add'])
            elif net == 'quic':
                point += pointTemplate['quic'].substitute(
                    security=__['host'], key=__['path'])

            if __['tls'] != '':
                point += '&tls=true'
        elif _ == 'ss':
            point = pointTemplate['shadowsocks'].substitute(
                index=str(index), method=__['method'], password=__['password'], add=__['add'], port=__['port'])
        elif _ == 'socks':
            point = pointTemplate['socks'].substitute(
                index=str(index), add=__['add'], port=__['port'], user=__['user'], password=__['password'])

        if point:
            print('; ' + __['ps'])
            print(point)
            index = index + 1


if __name__ == "__main__":
    url = input()
    v2ray = getV2ray(url)
    protocol, configuration = decode(v2ray)
    converter(protocol, configuration)
    print('[INFO] end')
